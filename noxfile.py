import nox


@nox.session(python=["3.7", "3.8"])
def testnosecret(session):
    # Only run tests that don't require secrets
    session.install("pytest", ".")
    session.run("pytest", "-m", "not secret")


@nox.session(python=["3.7", "3.8"])
def testsecret(session):
    # Only run tests that require secrets
    session.install("pytest", ".")
    session.run("pytest", "-m", "secret")


@nox.session(python=["3.8"])
def format(session):
    session.install("black")
    session.run("black", ".")


@nox.session(python=["3.8"])
def lint(session):
    session.install("flake8")
    session.run("flake8", "./hashcheck", "./test", "./examples")


@nox.session(python=["3.8"])
def audit(session):
    session.install("bandit")
    session.run("bandit", "-r", "./hashcheck", "./examples")
