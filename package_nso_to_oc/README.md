## NSO NED device configuration to OpenConfig

This python package will read in a json configuration for a device and translate to OpenConfig

### Usage
1. Decide whether pulling configuration from NSO or reading from file and set the appropriate envars
   - For NSO
   ```
   export NSO_URL="http://x.x.x.x:8080"
   export NSO_USERNAME=admin
   export NSO_PASSWORD=admin
   export NSO_DEVICE=router1
   export DEVICE_OS=xe
   export TEST=False   <- if True, the generated OC configuration is sent back to NSO
   export ACL_USE_EXISTING_SEQ=False   <- if True, existing ACL sequence numbers will be used. Could cause remark errors
   ```
   - For a file (to be used if you've previously pulled the NSO configuration)
   ```
   export NSO_NED_FILE="./device_configurations/$device_name/$device_name.json"
   export DEVICE_OS=xe
   ```
2. Execute script
   ```
   python3 main.py
   ```
3. The below files will be placed in a new directory names "output_data"
   - device_name.json = the full configuration is pulled from NSO
   - device_name_notes.txt = notes resulting from converting NSO config to OpenConfig
   - device_name_openconfig.json = New OpenConfig config
   - device_name_remaining.json = Remaining configuration from NSO

Ideally device_name_openconfig.json + device_name_remaining.json = device_name.json