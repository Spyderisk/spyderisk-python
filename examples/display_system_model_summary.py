# Import the spyderisk package
import spyderisk

# Define the file paths for the system and domain models.
system_m = "spyderisk/tests/data/router.nq.gz"
domain_m = "spyderisk/tests/data/domain-network-6a6-1-2.zip"

# Initialize the SystemModel with the provided system and domain model files.
# The SystemModel class provides a static representation of that system model.
system_model = spyderisk.SystemModel(system_m, domain_m)

# Print a summary of the system model, e.g. the 'info' attribute provides a
# summary of the system model. Other system model attributes and methods can be
# access in a similar way.
summary = system_model.info
print(summary)

# list model assets:
for asset in system_model.assets:
    print(f"Asset: {asset.description}")

