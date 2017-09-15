# -*- coding: utf-8 -*-

import six
import yara
import os
import hashlib
import tempfile
import shutil
import re

YARA_VERSION = 'v'+yara.__version__+' -- library: '+yara.__file__


class YaraSource:

    STATUS_UNKNOWN = 'UNKNOWN'
    STATUS_VALID = 'VALID'
    STATUS_BROKEN = 'BROKEN'
    STATUS_REPAIRED = 'REPAIRED'

    def __init__(self, **kwargs):
        '''
        :param source:
        :param path:
        :param namespace:
        :param include_name:
        :param buffer_dir:
        :param force_disk_buffering:
        '''
        source = kwargs['source'] if 'source' in kwargs else None
        path = kwargs['path'] if 'path' in kwargs else None
        if (source and path) or (not source and not path):
            raise SyntaxError('Expected either source or path (none or both '
                              'were provided)')
        if path is not None and not os.path.isabs(path):
            raise TypeError('YaraSource expects an absolute path')
        namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
        include_name = kwargs['include_name'] if 'include_name' in kwargs \
            else None
        buffer_dir = kwargs['buffer_dir'] if 'buffer_dir' in kwargs else None
        force_disk_buffering = bool(kwargs['force_disk_buffering']) if \
            'force_disk_buffering' in kwargs else False

        self._source = source
        self.path = path
        self._buffer_path = None
        self.namespace = namespace
        self.include_name = include_name

        self.status = self.STATUS_UNKNOWN
        self.error_data = None
        self.repaired_source = None

        if buffer_dir is not None: # FIXME check for duplicates
            if force_disk_buffering \
                    or self.include_name is not None:
                if self.include_name is not None:
                    write_fn = self.include_name
                else:
                    write_fn = hashlib.sha256(self.source.encode('utf-8'))\
                                   .hexdigest()+'.yara'
                write_dir = self.namespace if self.namespace is not None else ''
                write_path = os.path.join(str(buffer_dir),
                                          str(write_dir),
                                          str(write_fn))
                if self._is_file:
                    shutil.copy(write_fn, write_path)
                else:
                    with open(os.path.abspath(write_path), 'w') as f:
                        f.write(self.source)
                self._buffer_path = os.path.abspath(write_path)


    @property
    def source(self):
        if self._is_file:
            with open(self.path, 'r') as f:
                src = f.read()
        else:
            src = self._source
        return src

    @property
    def _is_file(self):
        return (self.path is not None)

    @property
    def _is_includable(self):
        return (self.include_name is not None)

    @property
    def _yara_compilable_rule(self):
        return self.source.encode('utf-8') if six.PY2 else self.source

    def __str__(self):
        rep = u'//       STATUS: {}\n'.format(self.status)
        if self.status == self.STATUS_BROKEN:
            rep += u'//       Error: {}\n'.format(self.error_data)
            rep += u'//\n{}\n'.format(self.source)
        elif self.status == self.STATUS_REPAIRED:
            rep += u'//       ORIGINAL:\n'
            rep += u'//       Error: {}\n'.format(self.error_data)
            for line in self.source.splitlines():
                rep += u'//\t\t\t{}\n'.format(line)
            rep += u'//\n{}\n'.format(self.repaired_source)
        else:
            rep += u'//\n{}\n'.format(self.source)
        return rep


class YaraValidator:

    def __init__(self, **kwargs):
        self._named_rules = {}
        self._anonymous_rules = []
        self._unprocessed = []
        self._TMP_CREATED = False
        self._CLEAR_TMP = kwargs['auto_clear'] if 'auto_clear' in kwargs \
            else False
        if 'disk_buffering' in kwargs:
            self._DISK_BUFFERING = True if kwargs['disk_buffering'] else False
        else:
            self._DISK_BUFFERING = not self.mem_only_supported()
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
        self._named_rules = {}
        self._anonymous_rules = []
        if self._TMP_CREATED:
            shutil.rmtree(self._includes_tmp_dir)

    def _register_rule(self, rule): # FIXME check for duplicates
        if rule._is_includable:
            self._named_rules[rule.namespace, rule.include_name] = rule
        else:
            self._anonymous_rules.append(rule)
        self._unprocessed.append(rule)

    def add_rule_source(self, source, namespace=None, include_name=None):
        if isinstance(source,YaraSource) \
                and namespace is None \
                and include_name is None:
            self._register_rule(source)
        else:
            yara_rule = YaraSource(source=source,
                                   namespace=namespace,
                                   include_name=include_name,
                                   buffer_dir=self._includes_tmp_dir,
                                   force_disk_buffering=self._DISK_BUFFERING)
            self._register_rule(yara_rule)

    def add_rule_file(self, path, namespace=None, include_name=None):
        if isinstance(path,YaraSource) \
                and namespace is None \
                and include_name is None:
            self._register_rule(path)
        else:
            yara_rule = YaraSource(false=path,
                                   namespace=namespace,
                                   include_name=include_name,
                                   buffer_dir=self._includes_tmp_dir,
                                   force_disk_buffering=self._DISK_BUFFERING)
            self._register_rule(yara_rule)

    def _incl_callback(self, requested_filename, filename, namespace):
        if (namespace, requested_filename) in self._named_rules:
            return self._named_rules[namespace, requested_filename].source
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
                if yara_rule._is_file:
                    yara.compile(yara_rule.path)
                else:
                    yara.compile(source=yara_rule._yara_compilable_rule)
            else:
                retry_with_includes = False
                try:
                    yara.compile(
                        source=yara_rule._yara_compilable_rule,
                        includes=False)
                except yara.SyntaxError as e:
                    if 'includes are disabled' in str(e):
                        if self.mem_only_supported():
                            yara.compile(source=yara_rule._yara_compilable_rule,
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
            yara_rule.status = YaraSource.STATUS_VALID
        except yara.SyntaxError as e:
            yara_rule.status = YaraSource.STATUS_BROKEN
            yara_rule.error_data = str(e)

    def check_all(self, accept_repairs=False):
        broken = []
        valid = []
        repaired = []
        anything_validated = True
        while anything_validated:
            anything_validated = False
            still_not_valid = []
            for yara_rule in self._unprocessed:
                self._validate(yara_rule)
                if yara_rule.status == YaraSource.STATUS_VALID:
                    valid.append(yara_rule)
                    anything_validated = True
                else:
                    self._repair(yara_rule)
                    if yara_rule.status == YaraSource.STATUS_REPAIRED:
                        repaired.append(yara_rule)
                        if accept_repairs \
                                and yara_rule.include_name is not None:
                            # FIXME no include_callback?
                            self._named_rules[yara_rule.namespace,
                                              yara_rule.include_name] = \
                                yara_rule.repaired_rule
                            anything_validated = True
                    else:
                        still_not_valid.append(yara_rule)
            self._unprocessed = still_not_valid
            broken.extend(self._unprocessed)
        self._unprocessed = []
        return valid, broken, repaired


    def _repair(self, rule):
        # FIXME if source fixed and rule is a file, copy new source to temp
        repaired_rule = rule
        prev_error = None
        max_tries = 5
        try_no = 0
        while try_no < max_tries \
                and repaired_rule.status == YaraSource.STATUS_BROKEN\
                and repaired_rule.error_data != prev_error:
            prev_error = repaired_rule.error_data
            try_no += 1
            decoded_source = repaired_rule.source
            suggested_src = self._suggest_repair(decoded_source,
                                                 repaired_rule.error_data)
            repaired_rule = YaraSource(source=suggested_src,
                                   namespace=rule.namespace,
                                   include_name=rule.include_name,
                                   buffer_dir=None)
            self._validate(repaired_rule)
        if repaired_rule != rule \
                and repaired_rule.status == YaraSource.STATUS_VALID:
            rule.status = YaraSource.STATUS_REPAIRED
            rule.repaired_source = repaired_rule.source

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
