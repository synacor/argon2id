all: git-hooks install

clean:
	rm -f .git/hooks/pre-commit

git-hooks: .git/hooks/pre-commit

.git/hooks/pre-commit:
	ln -s ../../git-hooks/pre-commit .git/hooks/pre-commit

install:
	go install ./...

.PHONY: all clean git-hooks install
