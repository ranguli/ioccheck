import os
import json
import vt
import pickle

client = vt.Client(os.getenv("API_KEY"))
eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

file_hash = client.get_object(f"/files/{eicar_sha256}")

#['DATE_ATTRIBUTES', 'context_attributes', 'crowdsourced_yara_results', 'first_seen_itw_date', 'first_submission_date', 'from_dict', 'get', 'id', 'last_analysis_date', 'last_analysis_results', 'last_analysis_stats', 'last_modification_date', 'last_submission_date', 'magic', 'md5', 'meaningful_name', 'names', 'popular_threat_classification', 'relationships', 'reputation', 'sandbox_verdicts', 'sha1', 'sha256', 'size', 'ssdeep', 'tags', 'times_submitted', 'tlsh', 'to_dict', 'total_votes', 'trid', 'type', 'type_description', 'type_extension', 'type_tag', 'unique_sources']


print(file_hash.reputation)
print(file_hash.sandbox_verdicts)
print(file_hash.total_votes)
print(file_hash.magic)

print(dict(file_hash.last_analysis_results))
print(dict(file_hash.last_analysis_stats))
print(file_hash.names)
print(file_hash.popular_threat_classifications)
print(file_hash.tlsh)
print(file_hash.trid)
print(file_hash.type)
print(file_hash.type_description)
print(file_hash.type_extension)
print(file_hash.type_tag)
print(file_hash.unique_sources)

#other_hash = client.get_object("/files/5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")

#print(other_hash.reputation)
#print(other_hash.sandbox_verdicts)
#print(other_hash.total_votes)
#print(other_hash.magic)
#print(other_hash.last_analysis_results)

