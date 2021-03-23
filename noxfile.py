from nox_poetry import session


@session(python=["3.7", "3.8", "3.9"])
def test(session):
    session.run("pytest", "--cov-report=xml", "--cov=ioccheck", external=True)


@session(python=["3.8"])
def lint(session):
    session.run("flake8", "./ioccheck", "./test", external=True)
    session.run("bandit", "-r", "./ioccheck", external=True)
    session.run("mypy", "./ioccheck", external=True)
    session.run("black", ".", external=True)
    session.run("isort", ".", external=True)


@session(python=["3.8"])
def docs(session):
    session.run(
        "sphinx-build", "-b", "html", "docs/source", "docs/build", external=True
    )
