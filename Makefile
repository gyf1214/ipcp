PYTHON=python3

PRELUDE=target/Projects.mk

METAFLAGS=
ifeq ($(DEBUG), 1)
METAFLAGS+=--debug
else
METAFLAGS+=--no-debug
endif
ifeq ($(TEST), 0)
METAFLAGS+=--no-test
else
METAFLAGS+=--test
endif

default : all

# avoid implicit rule
Makefile :
	$(NOOP)

$(PRELUDE) :
	@echo Prelude
	mkdir -p target
	$(PYTHON) buildscript/make.py $(METAFLAGS) >target/prelude.log

% : $(PRELUDE)
	$(MAKE) -f $(PRELUDE) $@

prelude : $(PRELUDE)
clean-prelude :
	@echo Clean prelude
	rm -fr $(PRELUDE)
rebuild-prelude : clean-prelude prelude

clean : $(PRELUDE) clean-all
	rm -fr target
all : clean-prelude
	$(MAKE) all-all
rebuild : clean all

test : all
	$(MAKE) test-test

container-test :
	podman build -t ipcp-dev:local -f Dockerfile .
	podman run --rm -v "$$PWD:/work" -w /work ipcp-dev:local bash -lc "make test"

integration-test : all
	bash test/integration/ipcpd_direct_test.sh

.PHONY : default all prelude clean-prelude rebuild-prelude clean rebuild test container-test integration-test
