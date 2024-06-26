package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/utils/ptr"

	"github.com/sirupsen/logrus"
	"github.com/wantedly/oauth2-proxy-manager/models"
)

type Controller struct {
	Clientset *kubernetes.Clientset
	Env       OAuth2ProxyEnv
	Ingress   IngressOption
}

type OAuth2ProxyEnv struct {
	Domain          string
	CookieDomain    string
	CookieSalt      string
	WhitelistDomain string
	Provider        string
	ClientID        string
	ClientSecret    string
}

type IngressOption struct {
	TLSSecretName string
	TLSHosts      string
	IngressClass  string
}

func makeController(clientset *kubernetes.Clientset) *Controller {
	return &Controller{
		Clientset: clientset,
		Env: OAuth2ProxyEnv{
			Domain:          os.Getenv("OAUTH2_PROXY_DOMAIN"),
			CookieDomain:    os.Getenv("COOKIE_DOMAIN"),
			CookieSalt:      os.Getenv("COOKIE_SALT"),
			WhitelistDomain: os.Getenv("WHITELIST_DOMAIN"),
			Provider:        os.Getenv("PROVIDER"),
			ClientID:        os.Getenv("OAUTH2_PROXY_CLIENT_ID"),
			ClientSecret:    os.Getenv("OAUTH2_PROXY_CLIENT_SECRET"),
		},
		Ingress: IngressOption{
			IngressClass:  os.Getenv("INGRESS_CLASS"),
			TLSSecretName: os.Getenv("TLS_SECRET_NAME"),
			TLSHosts:      os.Getenv("TLS_HOSTS"),
		},
	}
}

func NewController(clientset *kubernetes.Clientset) (*Controller, error) {
	// TODO: Handle error while extract Environment Variables...
	c := makeController(clientset)
	return c, nil
}

func (c *Controller) Apply(ctx context.Context, settings *models.ServiceSettings) {
	logrus.Infof("[Controller] Applying oauth2_proxy(%s)...", settings.AppName)
	c.applyService(ctx, settings)
	c.applySecret(ctx, settings)
	c.applyConfigMap(ctx, settings)
	c.applyDeployment(ctx, settings)
	c.applyIngress(ctx, settings)
}

func (c *Controller) Delete(settings *models.ServiceSettings) {
	logrus.Infof("[Controller] Delete oauth2_proxy(%s)", settings.AppName)
}

func (c *Controller) applyService(ctx context.Context, settings *models.ServiceSettings) {
	servicesClient := c.Clientset.CoreV1().Services("oauth2-proxy")
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName),
			Namespace: "oauth2-proxy",
		},
		Spec: apiv1.ServiceSpec{
			Type: apiv1.ServiceTypeNodePort,
			Ports: []apiv1.ServicePort{
				apiv1.ServicePort{
					Name:       "http",
					Port:       80,
					Protocol:   apiv1.ProtocolTCP,
					TargetPort: intstr.FromString("http"),
				},
			},
			Selector: map[string]string{
				"app": fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName),
			},
		},
	}
	logrus.Printf("[oauth2_proxy] Check Service...")
	result, err := servicesClient.Get(ctx, fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName), metav1.GetOptions{})
	if len(result.GetName()) == 0 {
		// NotFound
		logrus.Printf("[oauth2_proxy] Creating Service...")
		result, err = servicesClient.Create(ctx, service, metav1.CreateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Created Service! %q", result.GetObjectMeta().GetName())
	} else {
		logrus.Printf("[oauth2_proxy] Update Service...")

		// Inject ClusterIP
		logrus.Debugf("[oauth2_proxy] Detected ClusterIP: %s", result.Spec.ClusterIP)
		service.Spec.ClusterIP = result.Spec.ClusterIP

		// Inject ResourceVersion
		logrus.Debugf("[oauth2_proxy] Detected ResourceVersion: %s", result.GetResourceVersion())
		service.SetResourceVersion(result.GetResourceVersion())
		result, err = servicesClient.Update(ctx, service, metav1.UpdateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Updated Service! %q", result.GetObjectMeta().GetName())
	}

}

func (c *Controller) applyIngress(ctx context.Context, settings *models.ServiceSettings) {
	ingressClient := c.Clientset.NetworkingV1().Ingresses("oauth2-proxy")
	pathTypeImplementationSpecific := networkingv1.PathTypeImplementationSpecific
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oauth2-proxy",
			Namespace: "oauth2-proxy",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("nginx"),
			Rules: []networkingv1.IngressRule{
				networkingv1.IngressRule{
					Host: c.Env.Domain,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								networkingv1.HTTPIngressPath{
									Path:     fmt.Sprintf("/github/%s", settings.AppName),
									PathType: &pathTypeImplementationSpecific,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: fmt.Sprintf("oauth2-proxy-%s-%s-%s", c.Env.Provider, settings.GitHub.Organization, settings.AppName),
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if len(c.Ingress.IngressClass) != 0 {
		ingress.Spec.IngressClassName = &c.Ingress.IngressClass
	}

	if len(c.Ingress.TLSHosts) != 0 && len(c.Ingress.TLSSecretName) != 0 {
		ingress.Spec.TLS = []networkingv1.IngressTLS{
			networkingv1.IngressTLS{
				Hosts:      strings.Split(c.Ingress.TLSHosts, ","),
				SecretName: c.Ingress.TLSSecretName,
			},
		}
	}

	result, err := ingressClient.Get(ctx, "oauth2-proxy", metav1.GetOptions{})
	if len(result.GetName()) == 0 {
		// NotFound
		logrus.Printf("[oauth2_proxy] Creating Ingress...")

		result, err = ingressClient.Create(ctx, ingress, metav1.CreateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Created Ingress! %q", result.GetObjectMeta().GetName())
	} else {
		logrus.Printf("[oauth2_proxy] Update Ingress...")

		// Append New Entry
		for _, existPath := range result.Spec.Rules[0].IngressRuleValue.HTTP.Paths {
			if existPath.Path != ingress.Spec.Rules[0].IngressRuleValue.HTTP.Paths[0].Path {
				ingress.Spec.Rules[0].IngressRuleValue.HTTP.Paths = append(ingress.Spec.Rules[0].IngressRuleValue.HTTP.Paths, existPath)
			}
		}

		result, err = ingressClient.Update(ctx, ingress, metav1.UpdateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Updated Ingress! %q", result.GetObjectMeta().GetName())
	}
}

func (c *Controller) applySecret(ctx context.Context, settings *models.ServiceSettings) {
	secretClient := c.Clientset.CoreV1().Secrets("oauth2-proxy")
	cookieSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(
		c.Env.Provider+
			settings.GitHub.Organization+
			strings.Join(settings.GitHub.Teams, "")+
			settings.AppName+c.Env.CookieSalt,
	)))[0:32]
	secret := &apiv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName),
			Namespace: "oauth2-proxy",
		},
		Type: apiv1.SecretTypeOpaque,
		StringData: map[string]string{
			fmt.Sprintf("%s-%s-%s-cookie-secret", c.Env.Provider, settings.GitHub.Organization, settings.AppName): cookieSecret,
			"client-secret": c.Env.ClientSecret,
			"client-id":     c.Env.ClientID,
		},
	}
	logrus.Printf("[oauth2_proxy] Check Secret...")
	result, err := secretClient.Get(ctx, fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName), metav1.GetOptions{})
	if len(result.GetName()) == 0 {
		// NotFound
		logrus.Printf("[oauth2_proxy] Creating Secret...")
		result, err = secretClient.Create(ctx, secret, metav1.CreateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Created Secret! %q", result.GetObjectMeta().GetName())
	} else {
		logrus.Printf("[oauth2_proxy] Update Secret...")
		result, err = secretClient.Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Updated Secret! %q", result.GetObjectMeta().GetName())
	}
}

func (c *Controller) applyConfigMap(ctx context.Context, settings *models.ServiceSettings) {
	configMapClient := c.Clientset.CoreV1().ConfigMaps("oauth2-proxy")
	configMap := &apiv1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName),
			Namespace: "oauth2-proxy",
		},
		Data: map[string]string{
			"oauth2_proxy.cfg": "email_domains = [ \"*\" ]\nupstreams = [ \"file:///dev/null\" ]",
		},
	}
	logrus.Printf("[oauth2_proxy] Check ConfigMap...")
	result, err := configMapClient.Get(ctx, fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName), metav1.GetOptions{})
	if len(result.GetName()) == 0 {
		// NotFound
		logrus.Printf("[oauth2_proxy] Creating ConfigMap...")
		result, err = configMapClient.Create(ctx, configMap, metav1.CreateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Created ConfigMap! %q", result.GetObjectMeta().GetName())
	} else {
		logrus.Printf("[oauth2_proxy] Update ConfigMap...")
		result, err = configMapClient.Update(ctx, configMap, metav1.UpdateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Updated ConfigMap! %q", result.GetObjectMeta().GetName())
	}
}

func (c *Controller) applyDeployment(ctx context.Context, settings *models.ServiceSettings) {
	deploymentsClient := c.Clientset.AppsV1().Deployments("oauth2-proxy")
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName),
			Namespace: "oauth2-proxy",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName),
				},
			},
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName),
					},
				},
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						apiv1.Container{
							Name:  "oauth2-proxy",
							Image: "quay.io/oauth2-proxy/oauth2-proxy:v7.2.1",
							Args: []string{
								"--http-address=0.0.0.0:4180",
								fmt.Sprintf("--cookie-domain=%s", c.Env.CookieDomain),
								fmt.Sprintf("--cookie-name=_github_%s_%s_oauth2_proxy", settings.GitHub.Organization, settings.AppName),
								"--email-domain=*",
								fmt.Sprintf("--github-org=%s", settings.GitHub.Organization),
								fmt.Sprintf("--github-team=%s", strings.Join(settings.GitHub.Teams, ",")),
								fmt.Sprintf("--provider=github"),
								fmt.Sprintf("--proxy-prefix=/github/%s", settings.AppName),
								fmt.Sprintf("--redirect-url=https://%s/github/%s/callback", c.Env.Domain, settings.AppName),
								fmt.Sprintf("--upstream=file:///dev/null"),
								fmt.Sprintf("--whitelist-domain=%s", c.Env.WhitelistDomain),
								fmt.Sprintf("--config=/etc/oauth2_proxy/oauth2_proxy.cfg"),
							},
							Env: []apiv1.EnvVar{
								apiv1.EnvVar{
									Name: "OAUTH2_PROXY_CLIENT_ID",
									ValueFrom: &apiv1.EnvVarSource{
										SecretKeyRef: &apiv1.SecretKeySelector{
											LocalObjectReference: apiv1.LocalObjectReference{
												Name: fmt.Sprintf("oauth2-proxy-%s-%s-%s", c.Env.Provider, settings.GitHub.Organization, settings.AppName),
											},
											Key: "client-id",
										},
									},
								},
								apiv1.EnvVar{
									Name: "OAUTH2_PROXY_CLIENT_SECRET",
									ValueFrom: &apiv1.EnvVarSource{
										SecretKeyRef: &apiv1.SecretKeySelector{
											LocalObjectReference: apiv1.LocalObjectReference{
												Name: fmt.Sprintf("oauth2-proxy-%s-%s-%s", c.Env.Provider, settings.GitHub.Organization, settings.AppName),
											},
											Key: "client-secret",
										},
									},
								},
								apiv1.EnvVar{
									Name: "OAUTH2_PROXY_COOKIE_SECRET",
									ValueFrom: &apiv1.EnvVarSource{
										SecretKeyRef: &apiv1.SecretKeySelector{
											LocalObjectReference: apiv1.LocalObjectReference{
												Name: fmt.Sprintf("oauth2-proxy-%s-%s-%s", c.Env.Provider, settings.GitHub.Organization, settings.AppName),
											},
											Key: fmt.Sprintf("%s-%s-%s-cookie-secret", c.Env.Provider, settings.GitHub.Organization, settings.AppName),
										},
									},
								},
								apiv1.EnvVar{
									Name:  "OAUTH2_PROXY_SET_XAUTHREQUEST",
									Value: settings.SetXAuthRequest,
								},
							},
							Ports: []apiv1.ContainerPort{
								{
									Name:          "http",
									Protocol:      apiv1.ProtocolTCP,
									ContainerPort: 4180,
								},
							},
							LivenessProbe: &apiv1.Probe{
								InitialDelaySeconds: 0,
								TimeoutSeconds:      1,
								ProbeHandler: apiv1.ProbeHandler{
									HTTPGet: &apiv1.HTTPGetAction{
										Path: "/ping",
										Port: intstr.FromString("http"),
									},
								},
							},
							ReadinessProbe: &apiv1.Probe{
								InitialDelaySeconds: 0,
								TimeoutSeconds:      1,
								SuccessThreshold:    1,
								PeriodSeconds:       10,
								ProbeHandler: apiv1.ProbeHandler{
									HTTPGet: &apiv1.HTTPGetAction{
										Path: "/ping",
										Port: intstr.FromString("http"),
									},
								},
							},
							VolumeMounts: []apiv1.VolumeMount{
								apiv1.VolumeMount{
									Name:      "configmain",
									MountPath: "/etc/oauth2_proxy",
								},
							},
						},
					},
					Volumes: []apiv1.Volume{
						apiv1.Volume{
							Name: "configmain",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									DefaultMode: int32Ptr(420),
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: fmt.Sprintf("oauth2-proxy-%s-%s-%s", c.Env.Provider, settings.GitHub.Organization, settings.AppName),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create deployment...
	logrus.Printf("[oauth2_proxy] Check Deployment...")
	result, err := deploymentsClient.Get(ctx, fmt.Sprintf("oauth2-proxy-github-%s-%s", settings.GitHub.Organization, settings.AppName), metav1.GetOptions{})
	if len(result.GetName()) == 0 {
		// NotFound
		logrus.Printf("[oauth2_proxy] Creating Deployment...")
		result, err = deploymentsClient.Create(ctx, deployment, metav1.CreateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Created Deployment! %q", result.GetObjectMeta().GetName())
	} else {
		logrus.Printf("[oauth2_proxy] Update Deployment...")
		result, err = deploymentsClient.Update(ctx, deployment, metav1.UpdateOptions{})
		if err != nil {
			logrus.Error(err)
			return
		}
		logrus.Printf("[oauth2_proxy] Updated Deployment! %q", result.GetObjectMeta().GetName())
	}
}

func int32Ptr(i int32) *int32 { return &i }
