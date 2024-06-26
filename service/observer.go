package service

import (
	"context"
	"errors"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"

	"github.com/sirupsen/logrus"
	"github.com/wantedly/oauth2-proxy-manager/models"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

type Observer struct {
	Clientset  *kubernetes.Clientset
	Controller *Controller
}

func NewObserver(clientset *kubernetes.Clientset, controller *Controller) (*Observer, error) {
	observer := &Observer{
		Clientset:  clientset,
		Controller: controller,
	}
	return observer, nil
}

func (ob *Observer) Run(ctx context.Context) {
	logrus.Info("[Observer] Observing Ingress...")

	// create resource watcher (ingress)
	watcher := cache.NewListWatchFromClient(ob.Clientset.NetworkingV1().RESTClient(), "ingresses", v1.NamespaceAll, fields.Everything())

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
					ob.Controller.Apply(ctx, settings)
					//logrus.WithField("settings", settings).Info("Dummy: Update Deployment / ConfigMap / Service / Secret / Ingress")
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
					ob.Controller.Apply(ctx, settings)
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
					logrus.WithField("settings", settings).Info("Dummy: Delete Deployment / ConfigMap / Service / Secret / Ingress")
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

	if _, ok := meta.Annotations["oauth2-proxy-manager.k8s.io/app-name"]; !ok {
		return nil, errors.New("app-name not found. skip.")
	}

	if _, ok := meta.Annotations["oauth2-proxy-manager.k8s.io/github-org"]; !ok {
		return nil, errors.New("github-org not found. skip.")
	}

	if _, ok := meta.Annotations["oauth2-proxy-manager.k8s.io/github-teams"]; !ok {
		return nil, errors.New("github-teams not found. skip.")
	}

	setXAuthRequest, ok := meta.Annotations["oauth2-proxy-manager.k8s.io/set-xauthrequest"]
	if !ok {
		setXAuthRequest = ""
	}

	logrus.WithFields(logrus.Fields{
		"auth-url":         meta.Annotations["nginx.ingress.kubernetes.io/auth-url"],
		"auth-signin":      meta.Annotations["nginx.ingress.kubernetes.io/auth-signin"],
		"github-org":       meta.Annotations["oauth2-proxy-manager.k8s.io/github-org"],
		"github-teams":     meta.Annotations["oauth2-proxy-manager.k8s.io/github-teams"],
		"set-xauthrequest": setXAuthRequest,
	}).Debug("[ParseAnnotations]")

	settings := &models.ServiceSettings{
		AppName:         meta.Annotations["oauth2-proxy-manager.k8s.io/app-name"],
		AuthURL:         meta.Annotations["nginx.ingress.kubernetes.io/auth-url"],
		AuthSignIn:      meta.Annotations["nginx.ingress.kubernetes.io/auth-signin"],
		SetXAuthRequest: setXAuthRequest,
		GitHub: models.GitHubProvider{
			Organization: meta.Annotations["oauth2-proxy-manager.k8s.io/github-org"],
			Teams:        strings.Split(meta.Annotations["oauth2-proxy-manager.k8s.io/github-teams"], ","),
		},
	}

	return settings, nil
}
