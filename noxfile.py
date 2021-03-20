from nox_poetry import session


@session(python=['3.7', '3.8', '3.9'])
def test(session):
    session.run("pytest", "-m", "not secret")

@session(python=['3.7', '3.8', '3.9'])
def test_secret(session):
    session.run("pytest", "-m", "secret")


@session(python=['3.9'])
def coverage(session):
    session.run("pytest", "--cov-report=xml", "--cov=ioccheck", "-m", "not secret")


@session(python=['3.9'])
def lint(session):
    session.run("flake8", "./ioccheck", "./test")
    session.run("bandit", "-r", "./ioccheck")
    session.run("mypy", "./ioccheck")
    session.run("black", ".")
    session.run("isort", ".")


@session(python=['3.9'])
def docs(session):
    session.run(
        "sphinx-build",
        "-b",
        "html",
        "-b",
        "coverage",
        "./docs/source/",
        "docs/build/html/",
    )
