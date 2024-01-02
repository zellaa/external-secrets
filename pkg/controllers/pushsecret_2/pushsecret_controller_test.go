/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pushsecret

import (
	"context"
	"os"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	ctest "github.com/external-secrets/external-secrets/pkg/controllers/commontest"
	"github.com/external-secrets/external-secrets/pkg/controllers/pushsecret/psmetrics"
	"github.com/external-secrets/external-secrets/pkg/provider/testing/fake"
)

var (
	fakeProvider *fake.Client
	timeout      = time.Second * 10
	interval     = time.Millisecond * 250
)

type testCase struct {
	store      v1beta1.GenericStore
	pushsecret *v1alpha1.PushSecret
	secret     *v1.Secret
	assert     func(pushsecret *v1alpha1.PushSecret, secret *v1.Secret) bool
}

func init() {
	fakeProvider = fake.New()
	v1beta1.ForceRegister(fakeProvider, &v1beta1.SecretStoreProvider{
		Fake: &v1beta1.FakeProvider{},
	})
	psmetrics.SetUpMetrics()
}

func checkCondition(status v1alpha1.PushSecretStatus, cond v1alpha1.PushSecretStatusCondition) bool {
	for _, condition := range status.Conditions {
		if condition.Message == cond.Message &&
			condition.Reason == cond.Reason &&
			condition.Status == cond.Status &&
			condition.Type == cond.Type {
			return true
		}
	}
	return false
}

type testTweaks func(*testCase)

var _ = Describe("PushSecret controller", func() {
	const (
		PushSecretName  = "test-es"
		PushSecretStore = "test-store"
		SecretName      = "test-secret"
	)

	var PushSecretNamespace string

	// if we are in debug and need to increase the timeout for testing, we can do so by using an env var
	if customTimeout := os.Getenv("TEST_CUSTOM_TIMEOUT_SEC"); customTimeout != "" {
		if t, err := strconv.Atoi(customTimeout); err == nil {
			timeout = time.Second * time.Duration(t)
		}
	}

	BeforeEach(func() {
		var err error
		PushSecretNamespace, err = ctest.CreateNamespace("test-ns", k8sClient)
		Expect(err).ToNot(HaveOccurred())
		fakeProvider.Reset()
	})

	AfterEach(func() {
		k8sClient.Delete(context.Background(), &v1alpha1.PushSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      PushSecretName,
				Namespace: PushSecretNamespace,
			},
		})
		// give a time for reconciler to remove finalizers before removing SecretStores
		// TODO: Secret Stores should have finalizers bound to PushSecrets if DeletionPolicy == Delete
		time.Sleep(2 * time.Second)
		k8sClient.Delete(context.Background(), &v1beta1.SecretStore{
			ObjectMeta: metav1.ObjectMeta{
				Name:      PushSecretStore,
				Namespace: PushSecretNamespace,
			},
		})
		k8sClient.Delete(context.Background(), &v1beta1.ClusterSecretStore{
			ObjectMeta: metav1.ObjectMeta{
				Name: PushSecretStore,
			},
		})
		k8sClient.Delete(context.Background(), &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      SecretName,
				Namespace: PushSecretNamespace,
			},
		})
		Expect(k8sClient.Delete(context.Background(), &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: PushSecretNamespace,
			},
		})).To(Succeed())
	})

	makeDefaultTestcase := func() *testCase {
		return &testCase{
			pushsecret: &v1alpha1.PushSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      PushSecretName,
					Namespace: PushSecretNamespace,
				},
				Spec: v1alpha1.PushSecretSpec{
					SecretStoreRefs: []v1alpha1.PushSecretStoreRef{
						{
							Name: PushSecretStore,
							Kind: "SecretStore",
						},
					},
					Selector: v1alpha1.PushSecretSelector{
						Secret: v1alpha1.PushSecretSecret{
							Name: SecretName,
						},
					},
					Data: []v1alpha1.PushSecretData{
						{
							Match: v1alpha1.PushSecretMatch{
								SecretKey: "key",
								RemoteRef: v1alpha1.PushSecretRemoteRef{
									RemoteKey: "path/to/key",
								},
							},
						},
					},
				},
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: PushSecretNamespace,
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			store: &v1beta1.SecretStore{
				ObjectMeta: metav1.ObjectMeta{
					Name:      PushSecretStore,
					Namespace: PushSecretNamespace,
				},
				TypeMeta: metav1.TypeMeta{
					Kind: "SecretStore",
				},
				Spec: v1beta1.SecretStoreSpec{
					Provider: &v1beta1.SecretStoreProvider{
						Fake: &v1beta1.FakeProvider{
							Data: []v1beta1.FakeProviderData{},
						},
					},
				},
			},
		}
	}

	skipUnmanagedStore := func(tc *testCase) {
		tc.store = &v1beta1.SecretStore{
			TypeMeta: metav1.TypeMeta{
				Kind: "SecretStore",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      PushSecretStore,
				Namespace: PushSecretNamespace,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: v1beta1.SecretStoreSpec{
				Provider: &v1beta1.SecretStoreProvider{
					Fake: &v1beta1.FakeProvider{
						Data: []v1beta1.FakeProviderData{},
					},
				},
				Controller: "different-controller",
			},
		}
		tc.assert = func(ps *v1alpha1.PushSecret, secret *v1.Secret) bool {
			expected := v1alpha1.PushSecretStatusCondition{
				Type:    v1alpha1.PushSecretReady,
				Status:  v1.ConditionFalse,
				Reason:  v1alpha1.ReasonErrored,
				Message: "could not get SecretStore \"test-store\", secretstores.external-secrets.io \"test-store\" not found",
			}
			return checkCondition(ps.Status, expected)
		}
	}

	DescribeTable("When reconciling a PushSecret",
		func(tweaks ...testTweaks) {
			tc := makeDefaultTestcase()
			for _, tweak := range tweaks {
				tweak(tc)
			}
			ctx := context.Background()
			By("creating a secret store, secret and pushsecret")
			if tc.store != nil {
				Expect(k8sClient.Create(ctx, tc.store)).To(Succeed())
			}
			if tc.secret != nil {
				Expect(k8sClient.Create(ctx, tc.secret)).To(Succeed())
			}
			if tc.pushsecret != nil {
				Expect(k8sClient.Create(ctx, tc.pushsecret)).Should(Succeed())
			}
			time.Sleep(2 * time.Second)
			psKey := types.NamespacedName{Name: PushSecretName, Namespace: PushSecretNamespace}
			createdPS := &v1alpha1.PushSecret{}
			By("checking the pushSecret condition")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, psKey, createdPS)
				if err != nil {
					return false
				}
				return tc.assert(createdPS, tc.secret)
			}, timeout, interval).Should(BeTrue())
			// this must be optional so we can test faulty es configuration
		},
		Entry("should skip if unmanaged store", skipUnmanagedStore),
	)
})
