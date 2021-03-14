import nox


@nox.session(python=["3.7", "3.8"])
def tests(session):
    session.install("pytest", ".")
    session.run("pytest")


@nox.session(python=["3.8"])
def black(session):
    session.install("black")
    session.run("black", ".")


@nox.session(python=["3.8"])
def flake8(session):
    session.install("flake8")
    session.run("flake8", "./hashcheck", "./test", "./examples")


@nox.session(python=["3.8"])
def bandit(session):
    session.install("bandit")
    session.run("bandit", "-r", "./hashcheck", "./examples")
