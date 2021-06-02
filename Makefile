all:
	stack build

check: QA
	./QA

QA: QA.hs
	stack ghc --package haskell-src-exts --package ansi-terminal -- --make QA
