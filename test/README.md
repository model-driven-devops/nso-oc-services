## Testing Requirements

Commits and Pull requests must use conventional commits to pass testing pipeline. See here: https://www.conventionalcommits.org/en/v1.0.0/#summary


Install python(requirements.txt) and ansible collections(requirements.yml) required tooling from https://github.com/model-driven-devops/mdd

Build Lab using appropriate topology and ANSIBLE_CONFIG. For XE example:
```
export ANSIBLE_CONFIG=ansible_xe.cfg
```
Follow the lab deploying topology instructions from https://github.com/model-driven-devops/mdd/blob/main/exercises/deploy-topology.md

Set NSO Environment variables for testing playbooks:
```
export NSO_HOST=
export NSO_URL=
export NSO_USERNAME=
export NSO_PASSWORD=
export NSO_OS_USERNAME=
export NSO_OS_PASSWORD=
export NSO_DEVICES_USERNAME=
export NSO_DEVICES_PASSWORD=
```

Set appropriate NSO Device Environment Variable for testing topology (XE, XR, NX, etc), e.g.:
```
export XE1_HOST=
export XESWITCH1_HOST=
export XR1_HOST=
export NX1_HOST=
```

Configure ansible to use the appropriate inventory_dev for testing by setting the ANSIBLE_CONFIG. For example for XE:
```
export ANSIBLE_CONFIG=ansible_dev_xe.cfg
```

Run tests while skipping PyATS tasks not relative to OS(--skip-tags). For an XE example:
```
ansible-playbook tests/xe/xes1_stp.yml  --skip-tags="iosxr,nxos" -t stp_mstp -e api_method=PUT -e rollback=true -e assertion_ignore_errors=false 
```