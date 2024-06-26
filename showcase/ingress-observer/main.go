package main

import (
	"errors"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/rest"

	"github.com/sirupsen/logrus"
	"github.com/wantedly/oauth2-proxy-manager/logger"
	"github.com/wantedly/oauth2-proxy-manager/models"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	resource := "ingresses"

	logger.Init()

	logrus.Info("[Showcase] Observing Ingress...")

	var config *rest.Config

	_, err := rest.InClusterConfig()
	if err != nil {
		// Not Cluster
		kubeconfig := os.Getenv("KUBECONFIG")
		if len(kubeconfig) == 0 {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logrus.Panic(err)
		}
	} else {
		// In Cluster
		conf, err := rest.InClusterConfig()
		if err != nil {
			logrus.Fatalf("Failed get Kubernetes config: %v", err)
		}
		config = conf
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatal(err)
	}

	// create resource watcher (ingress)
	watcher := cache.NewListWatchFromClient(clientset.NetworkingV1().RESTClient(), resource, v1.NamespaceAll, fields.Everything())

	_, controller := cache.NewInformer(watcher, &networkingv1.Ingress{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				ing := obj.(*networkingv1.Ingress)
				meta := ing.ObjectMeta
				logrus.Infof("[Informer] Added Ingress %s", key)

				if !shouldPerform(ing) {
					return
				}

				settings, err := parseAnnotations(meta)
				if err == nil {
					logrus.WithField("settings", settings).Info("Dummy: Update Deployment / ConfigMap / Service / Secret / Ingress")
				}
			}
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)

			if err == nil {
				ing := new.(*networkingv1.Ingress)
				meta := ing.ObjectMeta
				logrus.Infof("[Informer] Update Ingress %s", key)

				if !shouldPerform(ing) {
					return
				}

				settings, err := parseAnnotations(meta)
				if err == nil {
					logrus.WithField("settings", settings).Info("Dummy: Update Deployment / ConfigMap / Service / Secret / Ingress")
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				ing := obj.(*networkingv1.Ingress)
				meta := ing.ObjectMeta
				logrus.Infof("[Informer] Delete Ingress: %s", key)

				if !shouldPerform(ing) {
					return
				}

				settings, err := parseAnnotations(meta)
				if err == nil {
					logrus.WithField("settings", settings).Info("Dummy: Update Deployment / ConfigMap / Service / Secret / Ingress")
				}
			}
		},
	})

	// Now let's start the controller
	stop := make(chan struct{})
	defer close(stop)
	go controller.Run(stop)

	// Wait forever
	select {}
}

func shouldPerform(ing *networkingv1.Ingress) bool {
	if ing == nil {
		logrus.Info("ingress is nil. skip.")
		return false
	}
	if ing.Spec.IngressClassName == nil {
		logrus.Info("ingress class is not found. skip.")
		return false
	}
	name := *ing.Spec.IngressClassName
	if name != "nginx" && name != "ingress-nginx" {
		logrus.Infof("ingress class is not `nginx` or `ingress-nginx` but %q. skip.", name)
		return false
	}
	return true
}

func parseAnnotations(meta metav1.ObjectMeta) (*models.ServiceSettings, error) {
	// Check Annotations ---
	if _, ok := meta.Annotations["nginx.ingress.kubernetes.io/auth-url"]; !ok {
		return nil, errors.New("auth-url not found. skip.")
	}

	if _, ok := meta.Annotations["nginx.ingress.kubernetes.io/auth-signin"]; !ok {
		return nil, errors.New("auth-signin not found. skip.")
	}

	if _, ok := meta.Annotations["oauth2-proxy-manager.lunasys.dev/github-org"]; !ok {
		return nil, errors.New("git/ub-org not found. skip.")
	}

	if _, ok := meta.Annotations["oauth2-proxy-manager.lunasys.dev/github-teams"]; !ok {
		return nil, errors.New("github-teams not found. skip.")
	}

	logrus.WithFields(logrus.Fields{
		"auth-url":     meta.Annotations["nginx.ingress.kubernetes.io/auth-url"],
		"auth-signin":  meta.Annotations["nginx.ingress.kubernetes.io/auth-signin"],
		"github-org":   meta.Annotations["oauth2-proxy-manager.lunasys.dev/github-org"],
		"github-teams": meta.Annotations["oauth2-proxy-manager.lunasys.dev/github-teams"],
	}).Debug("[ParseAnnotations]")

	settings := &models.ServiceSettings{
		AppName:    meta.Annotations["oauth2-proxy-manager.lunasys.dev/app-name"],
		AuthURL:    meta.Annotations["nginx.ingress.kubernetes.io/auth-url"],
		AuthSignIn: meta.Annotations["nginx.ingress.kubernetes.io/auth-signin"],
		GitHub: models.GitHubProvider{
			Organization: meta.Annotations["oauth2-proxy-manager.lunasys.dev/github-org"],
			Teams:        strings.Split(meta.Annotations["oauth2-proxy-manager.lunasys.dev/github-teams"], ","),
		},
	}

	return settings, nil
}
