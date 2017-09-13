# yara-validator

Validates yara rules and tries to repair the broken ones.

## Requirements
  * Python 2.7+ or 3.3+
  * yara and yara-python (PR [VirusTotal/yara-python#58](https://github.com/VirusTotal/yara-python/pull/58) and [VirusTotal/yara#727](https://github.com/VirusTotal/yara/pull/727) are recommended because they support include_callback)

## Usage
```python
import yara_validator

validator = yara_validator.YaraValidator(auto_clear=False)
validator.add_rule_source(u'rule FirstRule{condition: true}', 'namespace_1','first.yara')
validator.add_rule_source(u'include "first.yara" rule SecondRule{condition: true}')
validator.add_rule_file('/path/to/third.yara','namespace_1')
valid, broken, repaired = validator.check_all()

print(===== VALID RULES =====)
for rule in valid:
    print(u'{}'.format(rule.source))
print(===== BROKEN RULES =====)
for rule in broken:
    print(u'{}'.format(rule.source))
print(===== REPAIRED RULES =====)
for rule in repaired:
    print(u'{}'.format(rule.source))
```
Optional parameters for `YaraValidator.__init__()`:
 * `disk_buffering`: if set to True, allows the tool to use a temporary directory to copy sources and files before validation (requires write access to that directory). If set to False, nothing will be written to disk (requires a yara version supporting include_callback). If not set, will default to False if your yara version supports it, True otherwise.
 * `tmp_dir`: if `disk_buffering` is activated, forces the location where the temporary directory. Defaults to OS's temp.
 * `auto_clear`: if `disk_buffering` is activated, deletes the temporary directory once the `YaraValidator` object is destroyed.

`check_all()` can take one optional boolean parameter. If set to `True`, the suggested repairs will be automatically accepted: the repaired sources will be used instead of the original ones if any other rules includes them. **Setting this parameter to True may lead to rules not behaving as expected.**.
This function returns three lists: the valid rules, the broken rules and the repaired rules.
Rules in the list are instances of `YaraRule` with the following properties:
 * `source`: source code
 * `namespace`: rules namespace
 * `include_name`: name usable in Yara `include` directives
 * `status`: `YaraRule.STATUS_UNKNOWN`, `YaraRule.STATUS_VALID`, `YaraRule.STATUS_BROKEN` or `YaraRule.STATUS_REPAIRED`
 * `error_data`: if `STATUS_BROKEN` or `STATUS_REPAIRED`, contains the error message
 * `repaired_rule`: if `STATUS_REPAIRED`, contains a YaraRule with the repaired `source` and `STATUS_VALID`
