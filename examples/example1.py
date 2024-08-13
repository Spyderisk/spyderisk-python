import spyderisk

s_model = "spyderisk/tests/data/router.nq.gz"
d_model = "spyderisk/tests/data/domain-network-6a6-1-2.zip"

sm = spyderisk.SystemModel(s_model, d_model)

# print model summary
print(sm.info)

# show the number of model assets:
print(f"Model assets: {len(sm.assets)}")

# show the number of model threats:
print(f"Model threats: {len(sm.threats)}")
