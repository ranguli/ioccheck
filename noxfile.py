import nox


@nox.session(python=["3.7", "3.8", "3.9"])
def tests(session):
    session.install("pytest", ".")
    session.run("pytest")


@nox.session(python=["3.7", "3.8", "3.9"])
def flake8(session):
    session.install("flake8")
    session.run("flake8", "./hashcheck", "./test")
