# HaltSQL operator. Run from deploy/operator.
#
#   make manifests generate   regenerate CRDs, RBAC and deepcopy code
#   make test                 unit + envtest reconcile tests (real kube-apiserver)
#   make e2e                  kind end-to-end test (cluster "haltsql-operator")
#   make docker-build         build the operator image

REPO_ROOT       ?= $(abspath ../..)
LOCALBIN        ?= $(CURDIR)/bin
CONTROLLER_GEN  ?= $(LOCALBIN)/controller-gen
SETUP_ENVTEST   ?= $(LOCALBIN)/setup-envtest
CONTROLLER_TOOLS_VERSION ?= v0.20.1
SETUP_ENVTEST_VERSION    ?= release-0.23
ENVTEST_K8S_VERSION      ?= 1.35.0

# The haltsql CLI used as the validator in tests. Build it with
#   dune build --build-dir _build ./bin/haltsql/main.exe   (repo root)
HALTSQL_BIN     ?= $(REPO_ROOT)/_build/default/bin/haltsql/main.exe
HALTSQL_IMAGE   ?= haltsql-operator-e2e/haltsql:dev
IMG             ?= ghcr.io/ardada2468/haltsql-operator:latest

export GOTOOLCHAIN = local

.PHONY: all
all: manifests generate build

.PHONY: manifests
manifests: $(CONTROLLER_GEN) ## CRDs and the manager ClusterRole.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd paths="./..." \
	  output:crd:artifacts:config=config/crd/bases output:rbac:artifacts:config=config/rbac

.PHONY: generate
generate: $(CONTROLLER_GEN) ## DeepCopy methods.
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths="./api/..."

.PHONY: build
build:
	go build -o $(LOCALBIN)/manager ./cmd

.PHONY: vet
vet:
	go vet ./...
	go vet -tags e2e ./test/e2e/

.PHONY: envtest
envtest: $(SETUP_ENVTEST) ## Download kube-apiserver and etcd into bin/k8s.
	$(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN)/k8s -p path

.PHONY: test
test: manifests generate vet envtest ## Unit and envtest tests; fails if a prerequisite is missing.
	HALTSQL_BIN=$(HALTSQL_BIN) HALTSQL_REQUIRE_BINARY=1 HALTSQL_REQUIRE_ENVTEST=1 \
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN)/k8s -p path)" \
	go test ./api/... ./internal/... -count=1

.PHONY: e2e
e2e: ## kind end-to-end test; builds the images and deletes the cluster afterwards.
	HALTSQL_E2E=1 HALTSQL_IMAGE=$(HALTSQL_IMAGE) go test -tags e2e -v -count=1 -timeout 40m ./test/e2e/

.PHONY: docker-build
docker-build:
	docker build -t $(IMG) --build-arg HALTSQL_IMAGE=$(HALTSQL_IMAGE) .

.PHONY: install-manifests
install-manifests: ## Print the install manifests with IMG substituted.
	@kubectl kustomize config/default | sed 's|ghcr.io/ardada2468/haltsql-operator:latest|$(IMG)|'

$(CONTROLLER_GEN):
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

$(SETUP_ENVTEST):
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)
