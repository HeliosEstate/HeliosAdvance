.PHONY: check ci
check:
	bash check.sh
ci:
	bash check.sh --mutation
