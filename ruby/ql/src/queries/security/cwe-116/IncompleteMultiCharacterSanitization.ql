/**
 * @name Incomplete multi-character sanitization
 * @description A sanitizer that removes a sequence of characters may reintroduce the dangerous sequence.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.8
 * @precision high
 * @id rb/incomplete-multi-character-sanitization
 * @tags correctness
 *       security
 *       external/cwe/cwe-020
 *       external/cwe/cwe-080
 *       external/cwe/cwe-116
 */

import ruby
import codeql.ruby.security.performance.RegExpTreeView as RETV
import codeql.ruby.security.performance.ReDoSUtil as ReDoSUtil
import codeql.ruby.DataFlow
import codeql.ruby.frameworks.core.String

/**
 * A regexp term that matches substrings that should be replaced with the empty string.
 */
class EmptyReplaceRegExpTerm extends RETV::RegExpTerm {
  EmptyReplaceRegExpTerm() {
    exists(String::ReplaceCall replace, DataFlow::LocalSourceNode node |
      node.asExpr().getConstantValue().isString("") and
      node.flowsTo(replace.getReplacement()) and
      this = replace.getRegExp().getParsed().getAChild*()
    )
  }
}

/**
 * A prefix that may be dangerous to sanitize explicitly.
 *
 * Note that this class exists solely as a (necessary) optimization for this query.
 */
class DangerousPrefix extends string {
  DangerousPrefix() {
    this = ["/..", "../"] or
    this = "<!--" or
    this = "<" + ["iframe", "script", "cript", "scrip", "style"] or
    this = "<%"
  }
}

/**
 * A substring of a prefix that may be dangerous to sanitize explicitly.
 */
class DangerousPrefixSubstring extends string {
  DangerousPrefixSubstring() {
    exists(DangerousPrefix s | this = s.substring([0 .. s.length()], [0 .. s.length()]))
  }
}

/**
 * Gets a dangerous prefix that is in the prefix language of `t`.
 */
DangerousPrefix getADangerousMatchedPrefix(EmptyReplaceRegExpTerm t) {
  result = getADangerousMatchedPrefixSubstring(t) and
  not exists(EmptyReplaceRegExpTerm pred |
    pred = t.getPredecessor+() and not pred.matchesEmptyString()
  )
}

pragma[noinline]
DangerousPrefixSubstring getADangerousMatchedChar(EmptyReplaceRegExpTerm t) {
  t.matchesEmptyString() and result = ""
  or
  t.matches(result)
  or
  // A substring matched by some character class. This is only used to match the "word" part of a HTML tag (e.g. "iframe" in "<iframe").
  exists(ReDoSUtil::CharacterClass cc |
    cc = ReDoSUtil::getCanonicalCharClass(t) and
    cc.matches(result) and
    result.regexpMatch("\\w") and
    // excluding character classes that match ">" (e.g. /<[^<]*>/), as these might consume nested HTML tags, and thus prevent the dangerous pattern this query is looking for.
    not cc.matches(">")
  )
  or
  t instanceof RETV::RegExpDot and
  result.length() = 1
  or
  (
    t instanceof RETV::RegExpOpt or
    t instanceof RETV::RegExpStar or
    t instanceof RETV::RegExpPlus or
    t instanceof RETV::RegExpGroup or
    t instanceof RETV::RegExpAlt
  ) and
  result = getADangerousMatchedChar(t.getAChild())
}

/**
 * Gets a substring of a dangerous prefix that is in the language starting at `t` (ignoring lookarounds).
 *
 * Note that the language of `t` is slightly restricted as not all RegExpTerm types are supported.
 */
DangerousPrefixSubstring getADangerousMatchedPrefixSubstring(EmptyReplaceRegExpTerm t) {
  result = getADangerousMatchedChar(t) + getADangerousMatchedPrefixSubstring(t.getSuccessor())
  or
  result = getADangerousMatchedChar(t)
  or
  // loop around for repetitions (only considering alphanumeric characters in the repetition)
  exists(RepetitionMatcher repetition | t = repetition |
    result = getADangerousMatchedPrefixSubstring(repetition) + repetition.getAChar()
  )
}

class RepetitionMatcher extends EmptyReplaceRegExpTerm {
  string char;

  pragma[noinline]
  RepetitionMatcher() {
    (this instanceof RETV::RegExpPlus or this instanceof RETV::RegExpStar) and
    char = getADangerousMatchedChar(this.getAChild()) and
    char.regexpMatch("\\w")
  }

  pragma[noinline]
  string getAChar() { result = char }
}

/**
 * Holds it `t` may match the dangerous `prefix` and some suffix, indicating intent to prevent a vulnerability of kind `kind`.
 */
predicate matchesDangerousPrefix(EmptyReplaceRegExpTerm t, string prefix, string kind) {
  prefix = getADangerousMatchedPrefix(t) and
  (
    kind = "path injection" and
    prefix = ["/..", "../"] and
    // If the regex is matching explicit path components, it is unlikely that it's being used as a sanitizer.
    not t.getSuccessor*().getAMatchedString().regexpMatch("(?is).*[a-z0-9_-].*")
    or
    kind = "HTML element injection" and
    (
      // comments
      prefix = "<!--" and
      // If the regex is matching explicit textual content of an HTML comment, it is unlikely that it's being used as a sanitizer.
      not t.getSuccessor*().getAMatchedString().regexpMatch("(?is).*[a-z0-9_].*")
      or
      // specific tags
      // the `cript|scrip` case has been observed in the wild several times
      prefix = "<" + ["iframe", "script", "cript", "scrip", "style"]
    )
    or
    // ERb
    kind = "ERb injection" and
    prefix = "<?"
  )
  or
  kind = "HTML attribute injection" and
  prefix =
    [
      // ordinary event handler prefix
      "on",
      // angular prefixes
      "ng-", "ng:", "data-ng-", "x-ng-"
    ] and
  (
    // explicit matching: `onclick` and `ng-bind`
    t.getAMatchedString().regexpMatch("(?i)" + prefix + "[a-z]+")
    or
    // regexp-based matching: `on[a-z]+`
    exists(EmptyReplaceRegExpTerm start | start = t.getAChild() |
      start.getAMatchedString().regexpMatch("(?i)[^a-z]*" + prefix) and
      isCommonWordMatcher(start.getSuccessor())
    )
  )
}

/**
 * Holds if `t` is a common pattern for matching words
 */
predicate isCommonWordMatcher(RETV::RegExpTerm t) {
  exists(RETV::RegExpTerm quantified | quantified = t.(RETV::RegExpQuantifier).getChild(0) |
    // [a-z]+ and similar
    quantified
        .(RETV::RegExpCharacterClass)
        .getAChild()
        .(RETV::RegExpCharacterRange)
        .isRange(["a", "A"], ["z", "Z"])
    or
    // \w+ or [\w]+
    [quantified, quantified.(RETV::RegExpCharacterClass).getAChild()]
        .(RETV::RegExpCharacterClassEscape)
        .getValue() = "w"
  )
}

from
  String::ReplaceCall replace, EmptyReplaceRegExpTerm regexp, EmptyReplaceRegExpTerm dangerous,
  string prefix, string kind
where
  regexp = replace.getRegExp().getParsed() and
  dangerous.getRootTerm() = regexp and
  // skip leading optional elements
  not dangerous.matchesEmptyString() and
  // only warn about the longest match
  prefix = max(string m | matchesDangerousPrefix(dangerous, m, kind) | m order by m.length(), m) and
  // only warn once per kind
  not exists(EmptyReplaceRegExpTerm other |
    other = dangerous.getAChild+() or other = dangerous.getPredecessor+()
  |
    matchesDangerousPrefix(other, _, kind) and
    not other.matchesEmptyString()
  ) and
  // TODO: avoid anchored terms
  not exists(RETV::RegExpCaret c | regexp = c.getRootTerm()) and
  not exists(RETV::RegExpDollar d | regexp = d.getRootTerm())
select replace, "This string may still contain $@, which may cause a " + kind + " vulnerability.",
  dangerous, prefix
