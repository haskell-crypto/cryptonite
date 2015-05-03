all:
	cabal build

check: QA
	./QA

QA: QA.hs
	ghc --make QA
