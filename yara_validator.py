# -*- coding: utf-8 -*-

import six
import yara
import os
import hashlib
import tempfile
import shutil
from contextlib import contextmanager
import re

YARA_VERSION = 'v'+yara.__version__+' -- library: '+yara.__file__


class YaraRule(object):

    STATUS_UNKNOWN = 0
    STATUS_VALID = 1
    STATUS_BROKEN = 2
    STATUS_REPAIRED = 3

    def __init__(self, data, namespace, include_name):
        # TODO investigate behaviour when virtual_filename is in fact a path
        if namespace is None:
            namespace = 'default'
        self.data = data
        self.namespace = namespace
        self.include_name = include_name
        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.repaired_rule = None

    @property
    def compilable_rule(self):
        return self.source.encode('utf-8') if six.PY2 else self.source

class YaraSource(YaraRule):

    def __init__(self, source, namespace=None, include_name=None):
        if include_name is None:
            include_name = hashlib.sha256(source.encode('utf-8')).hexdigest()\
                           + '.yara'
        YaraRule.__init__(self, source, namespace, include_name)

    def to_file(self, folder):  # TODO needs safeguard
        with open(os.path.join(folder, self.include_name), 'w') as f:
            f.write(self.source)
            path = os.path.realpath(f.name)
        return YaraFile(path, self.namespace, self.include_name)

    @property
    def source(self):
        return self.data


class YaraFile(YaraRule):

    def __init__(self, path, namespace=None, include_name=None):
        if include_name is None:
            include_name = os.path.basename(path)
        YaraRule.__init__(self, path, namespace, include_name)
        self.path = path

    @property
    def source(self):
        with open(self.path, 'r') as f:
            source = f.read()
        return source


class YaraValidator:

    def __init__(self, **kwargs):
        self._all_rules = {}
        self._unprocessed = {}
        self._TMP_CREATED = False
        self._CLEAR_TMP = kwargs['auto_clear'] if 'auto_clear' in kwargs \
            else False
        if 'disk_buffering' in kwargs:
            self._DISK_BUFFERING = True if kwargs['disk_buffering'] else False
        else:
            self._DISK_BUFFERING = not self.mem_only_supported()
        self._current_namespace = 'default'
        if self._DISK_BUFFERING:
            tmp_dir = kwargs['tmp_dir'] if 'tmp_dir' in kwargs else None
            self._includes_tmp_dir = tempfile.mkdtemp(dir=tmp_dir)
            self._TMP_CREATED = True
        else:
            self._includes_tmp_dir = None

    def __del__(self):
        if self._CLEAR_TMP:
            self.clear_tmp()

    def clear_tmp(self):
        self._all_rules = {}
        if self._TMP_CREATED:
            shutil.rmtree(self._includes_tmp_dir)

    def _register_rule(self, rule):
        if (rule.namespace, rule.include_name) not in self._all_rules:
            self._all_rules[rule.namespace, rule.include_name] = rule
            self._unprocessed[rule.namespace, rule.include_name] = rule
        elif self._all_rules[rule.namespace,
                             rule.include_name].source != rule.source:
            raise Exception("Rules '{}' already registered in namespace '{}'"
                            .format(rule.include_name, rule.namespace))

    def add_rule_source(self, source, namespace=None, include_name=None):
        yara_rule = YaraSource(source, namespace, include_name)
        with self._ch_namespace(yara_rule.namespace):
            if self._DISK_BUFFERING:
                yara_rule = yara_rule.to_file(os.getcwd())
            self._register_rule(yara_rule)

    def add_rule_file(self, path, namespace=None, include_name=None):
        yara_file = YaraFile(path, namespace, include_name)
        with self._ch_namespace(yara_file.namespace):
            if self._DISK_BUFFERING:
                shutil.copy(yara_file.path, os.getcwd())
            self._register_rule(yara_file)

    def _incl_callback(self, requested_filename, filename, namespace):
        if (namespace, requested_filename) in self._all_rules:
            return self._all_rules[namespace, requested_filename]
        else:
            return None

    def mem_only_supported(self):
        try:
            yara.compile(source='', include_callback=lambda _: '')
            return True
        except TypeError as e:
            if str(e) == "'include_callback' is an invalid keyword argument " \
                         "for this function":
                return False
            raise  # should not happen

    def _validate(self, yara_rule):
        try:
            if self._DISK_BUFFERING:
                if isinstance(yara_rule, YaraFile):
                    yara.compile(yara_rule.path)
                elif isinstance(yara_rule, YaraSource):
                    yara.compile(source=yara_rule.compilable_rule)
            else:
                retry_with_includes = False
                try:
                    yara.compile(source=yara_rule.compilable_rule,
                        includes=False)
                except yara.SyntaxError as e:
                    if 'includes are disabled' in str(e):
                        if self.mem_only_supported():
                            yara.compile(source=yara_rule.compilable_rule,
                                         include_callback=self._incl_callback)
                        else:
                            retry_with_includes = True
                    else:
                        raise
                if retry_with_includes:
                    raise NotImplementedError(
                        "Installed yara version does not support "
                        "'include_callback'.\n\tUse "
                        "https://github.com/VirusTotal/yara/pull/727 "
                        "along with the corresponding yara-python.\n\t"
                        "Or use YaraValidator with the "
                        "'disk_buffering' option (requires 'rw' access "
                        "to disk)."
                    )
            yara_rule.status = YaraRule.STATUS_VALID
        except yara.SyntaxError as e:
            yara_rule.status = YaraRule.STATUS_BROKEN
            yara_rule.error_data = str(e)

    def check_all(self, accept_repairs=False):
        broken = {}
        valid = {}
        repaired = {}
        anything_validated = True
        while anything_validated:
            anything_validated = False
            still_not_valid = dict(self._unprocessed)
            for (namespace, include_name) in self._unprocessed:
                with self._ch_namespace(namespace):
                    if namespace not in valid:
                        valid[namespace] = []
                    if namespace not in broken:
                        broken[namespace] = []
                    if namespace not in repaired:
                        repaired[namespace] = []

                    yara_rule = self._unprocessed[namespace, include_name]
                    self._validate(yara_rule)
                    if yara_rule.status == YaraRule.STATUS_VALID:
                        valid[namespace].append(yara_rule)
                        del still_not_valid[namespace, include_name]
                        anything_validated = True
                    else:
                        self._repair(yara_rule)
                        if yara_rule.status == YaraRule.STATUS_REPAIRED:
                            repaired[namespace].append(yara_rule)
                            del still_not_valid[namespace, include_name]
                            if accept_repairs:
                                self._all_rules[namespace, include_name] = \
                                    yara_rule.repaired_rule
                                anything_validated = True
            self._unprocessed = still_not_valid
        for namespace, include_name in self._unprocessed:
            broken[namespace].append(self._unprocessed[namespace, include_name])
        self._unprocessed = {}
        return valid, broken, repaired

    @contextmanager
    def _ch_namespace(self, namespace):
        old_namespace = self._current_namespace
        self._current_namespace = namespace
        if self._DISK_BUFFERING:
            old_dir = os.getcwd()
            if namespace and self._includes_tmp_dir:
                working_dir = os.path.abspath(
                    os.path.join(self._includes_tmp_dir, namespace)
                )
            elif self._includes_tmp_dir:
                working_dir = os.path.abspath(self._includes_tmp_dir)
            else:
                working_dir = os.getcwd()
            # prevents directory traversal, not enforced by yara itself
            if os.path.commonprefix([working_dir, self._includes_tmp_dir]) \
                    != self._includes_tmp_dir:
                raise Exception('Directory traversal not allowed to {}'
                                .format(working_dir))
            if not os.path.exists(working_dir):
                os.makedirs(working_dir)
            os.chdir(working_dir)
            yield
            os.chdir(old_dir)
        else:
            yield
        self._current_namespace = old_namespace

    def _repair(self, rule):
        repaired_rule = rule
        prev_error = None
        max_tries = 5
        try_no = 0
        while try_no < max_tries \
                and repaired_rule.status == YaraRule.STATUS_BROKEN\
                and repaired_rule.error_data != prev_error:
            prev_error = repaired_rule.error_data
            try_no += 1
            decoded_source = repaired_rule.source
            suggested_src = self._suggest_repair(decoded_source,
                                                 repaired_rule.error_data)
            repaired_rule = YaraSource(suggested_src,
                                       repaired_rule.namespace,
                                       repaired_rule.include_name)
            self._validate(repaired_rule)
        if repaired_rule != rule \
                and repaired_rule.status == YaraRule.STATUS_VALID:
            rule.status = YaraRule.STATUS_REPAIRED
            rule.repaired_rule = repaired_rule

    def _suggest_repair(self, rule_source, error_msg):

        common_misspelled_keywords = {
            u'Rule ': u'rule ',
            u'Meta:': u'meta:',
            u'Strings:': u'strings:',
            u'Condition:': u'condition:',
            u'meta=': u'meta:',
            u'strings=': u'strings:',
            u'condition=': u'condition:',
            u'“': u'"',
            u'”': u'"',
            u'″': u'"',
            u'‶': u'"'

        }
        base_modules = {
            'pe': u'import "pe"',
            'elf': u'import "elf"',
            'cuckoo': u'import "cuckoo"',
            'magic': u'import "magic"',
            'hash': u'import "hash"',
            'math': u'import "math"',
            'dotnet': u'import "dotnet"'
        }
        repaired = rule_source

        # FIXING COMMON ISSUE: common misspells
        #       FIXME: make precise matching to avoid replacing legit quote-like
        #              characters in unicode strings
        for misspell in common_misspelled_keywords:
            repaired = repaired.replace(misspell,
                                        common_misspelled_keywords[misspell])

        # FIXING COMMON ISSUE: missing modules imports
        for mod in base_modules:
            if 'undefined identifier "{}"'.format(mod) in error_msg:
                repaired = base_modules[mod]+'\n'+repaired

        # FIXING COMMON ISSUE:
        #       yara bug where hex (sub)strings fail to compile when [ ] is
        #       terminating the (sub)string.
        #       example:    replacing FF (FF | [2]) FF [5]
        #                   with FF (FF | ?? ??) FF ?? ?? ?? ?? ??
        #       FIXME: no clean solution yet for ranges. e.g.: [3-5]
        #       FIXME: pre-fix similar issues in other hex strings potentially
        #              presenting the same issue
        bytestring_error = re.search(
            r"line (.*): invalid hex string \"(\$.*)\":", error_msg)
        if bytestring_error:
            string_name = bytestring_error.group(2)
            regex = re.escape(string_name)+r'.*?=.*?{(.*?)}.*?$'
            hex_string = re.search(regex, repaired, re.MULTILINE | re.DOTALL)
            if hex_string:
                stripped_hex_string = hex_string.group(1)
                stripped_hex_string = re.sub(r'\s*', '', stripped_hex_string)
                fixed_hex_string = re.sub(r'\[([0-9]+)\]',
                                          lambda m:
                                          ''.join('?? '*int(s) for n, s
                                                  in enumerate(m.groups())),
                                          stripped_hex_string)
                fixed_statement = string_name + ' = { ' + fixed_hex_string + '}'
                repaired = repaired.replace(hex_string.group(0),
                                            fixed_statement)

        # FIXING COMMON ISSUE: random line breaks appearing in the middle of
        #       strings or meta. Makes the rule a one-liner, then re-insert
        #       line breaks appropriately
        #       FIXME: write or find a proper fault-tolerant lexer for rules
        #       FIXME: handle multiple rules defined in a single string
        elif re.search(r'line (.*): '
                       r'(?:syntax error, unexpected \$end'
                       r'|unterminated string)',
                       error_msg):
            repaired_without_comments = self.__strip_comments(repaired)
            repaired = repaired_without_comments\
                .replace('\r', '')\
                .replace('\n', '')
            repaired = repaired\
                .replace('meta:', '\nmeta: ')\
                .replace('strings:', '\nstrings: ')\
                .replace('condition:', '\ncondition:\n ')
            meta_section = re.search(r'^\s*meta:\s+(.*?)$',
                                     repaired,
                                     re.MULTILINE)
            strings_section = re.search(r'^\s*strings:\s+(.*?)$',
                                        repaired,
                                        re.MULTILINE)
            if meta_section:
                meta_content = meta_section.group(1)
                meta_entries = re.findall(
                    r'.+?\s*=\s*(?:"(?:\\.|[^"\\])*"|[0-9]+\s+)', meta_content)
                formatted_meta_entries = \
                    '\n\t'.join([entry.strip() for entry in meta_entries])
                repaired = repaired.replace(meta_section.group(0),
                                            u"meta:\n\t{}"
                                            .format(formatted_meta_entries)
                                            )
            if strings_section:
                strings_content = strings_section.group(1)
                strings_entries = re.findall(
                    r'(\$[\w\s]*=\s*(?:(?:".+?").*?|(?:{.+?}).*?|(?:/.+?/).*?)(?=\$|$))',
                    strings_content)
                formatted_strings_entries = \
                    '\n\t'.join([entry.strip() for entry in strings_entries])
                repaired = repaired.replace(strings_section.group(0),
                                            u"strings:\n\t{}"
                                            .format(formatted_strings_entries))

        # FIXING COMMON ISSUE: rule names containing spaces
        #      FIXME: handle multiple rules defined in a single string
        elif error_msg.strip() == "line 1: syntax error, unexpected " \
                                  "_IDENTIFIER_, expecting '{'" \
                and len(repaired.splitlines()) > 1:
            lines = repaired.splitlines()
            matched_rulename = re.search(r'^\s*rule\s*(.*)\s*{$', lines[0])
            first_line_brackets = '{'
            if not matched_rulename:
                matched_rulename = re.search(r'^\s*rule\s*(.*)\s*$', lines[0])
                first_line_brackets = ''
            if matched_rulename:
                lines[0] = u'rule '\
                           +matched_rulename.group(1).replace(' ', '')\
                           +first_line_brackets
                repaired = u'\n'.join(lines)

        return repaired

    @staticmethod
    def __strip_comments(rule_string):
        regex = r"(\".*?(?<!\\)\"|\'.*?(?<!\\)\')|(/\*.*?\*/|//[^\r\n]*$)|(^\s*//.*?$)"
        comp_regex = re.compile(regex, re.MULTILINE | re.DOTALL)

        def _replacer(match):
            if match.group(2) is not None:
                return ""
            else:
                return match.group(1)

        return comp_regex.sub(_replacer, rule_string)
