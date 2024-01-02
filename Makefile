PYTHON=python3

PRELUDE=target/Projects.mk

METAFLAGS=
ifeq ($(DEBUG), 1)
METAFLAGS+=--debug
else
METAFLAGS+=--no-debug
endif
ifeq ($(TEST), 1)
METAFLAGS+=--test
else
METAFLAGS+=--no-test
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

.PHONY : default all prelude clean-prelude rebuild-prelude clean rebuild test
