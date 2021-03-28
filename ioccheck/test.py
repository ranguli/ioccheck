from ioccheck.iocs import Hash
from ioccheck.services import Twitter


sample = Hash("94e865c9a7a8f0ea2de2c46f146db82993babf3b706f36ded2aca67c67990004")

sample.check(services=[Twitter])

print(sample.reports.twitter.tweets)
