PRE := HyperCrypt

all:
	@$(MAKE) -C $(PRE)Lib
	@$(MAKE) -C $(PRE)Cli
	@mv $(PRE)Cli/hypercrypt .

clean:
	@$(MAKE) -C $(PRE)Lib clean
	@$(MAKE) -C $(PRE)Cli clean
	@rm -f hypercrypt

