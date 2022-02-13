# CVE-2019-10756
def m(content)
  content = content.gsub(/<.*cript.*\/scrip.*>/i, "") # NOT OK
  content = content.gsub(/ on\w+=".*"/, "") # NOT OK
  content = content.gsub(/ on\w+=\'.*\'/, "") # NOT OK
  content
end

def m(content)
  content = content.gsub(/<.*cript.*/i, "") # NOT OK
  content = content.gsub(/.on\w+=.*".*"/, "") # NOT OK
  content = content.gsub(/.on\w+=.*\'.*\'/, "") # NOT OK

  content
end

# CVE-2020-7656
def m(text)
  rscript = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i
  text.gsub(rscript, "") # NOT OK
  text
end

# CVE-2019-1010091
def m(text)
  text.gsub(/<!--|--!?>/, "") # NOT OK
end

def m(text)
  while /<!--|--!?>/.match?(text)
    text = text.gsub(/<!--|--!?>/, "") # OK
  end

  text
end

# CVE-2019-10767
def m(id)
  id.gsub(/\.\./, "") # OK (can not contain '..' afterwards)
end

def m(id)
  id.gsub(/[\]\[*,'"`<>\\?\/]/, "") # OK (or is it?)
end

# CVE-2019-8903
def m(req)
  REG_TRAVEL = /(\/)?\.\.\//
  req.url = req.url.gsub(REG_TRAVEL, "") # NOT OK
end

# New cases

def m(x)
  x = x.gsub(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/, "") # NOT OK

  x = x.gsub(/(\/|\s)on\w+=(\'|")?[^"]*(\'|")?/, "") # NOT OK

  x = x.gsub(/<\/script>/, "") # OK

  x = x.gsub(/<(.)?br(.)?>/, "") # OK
  x = x.gsub(/<\/?b>/, "") # OK
  x = x.gsub(/<(ul|ol)><\/(ul|ol)>/i, "") # OK
  x = x.gsub(/<li><\/li>/i, "") # OK

  x = x.gsub(/<!--(.*?)-->/m, "") # NOT OK
  x = x.gsub(/\sng-[a-z-]+/, "") # NOT OK
  x = x.gsub(/\sng-[a-z-]+/, "") # NOT OK (ng-attributes)

  x = x.gsub(/(<!--\[CDATA\[|\]\]-->)/, "\n") # OK: not a sanitizer

  x = x.gsub(/<script.+desktop\-only.+<\/script>/, "") # OK [INCONSISTENCY]
  x = x.gsub(/<script async.+?<\/script>/, "") # OK
  x = x.gsub(/<!--[\s\S]*?-->|<\?(?:php)?[\s\S]*?\?>/i, "") # NOT OK

  x = x.gsub(/\x2E\x2E\x2F\x2E\x2E\x2F/, "") # NOT OK (matches "../../")

  x = x.gsub(/<script.*>.*<\/script>/i, "") # NOT OK

  x = x.gsub(/^(\.\.\/?)+/, "") # OK

  # NOT OK
  x = x.gsub(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/) do |match|
      if unknown then match else "" end
  end

  x = x.gsub(/<\/?([a-z][a-z0-9]*)\b[^>]*>/i, "") # NOT OK [INCONSISTENCY]

  x = x.gsub(/\.\./, "") # OK
  x = x.gsub(/\.\.\//, "") # NOT OK
  x = x.gsub(/\/\.\./, "") # NOT OK

  x = x.gsub(/<script(.*?)>([\s\S]*?)<\/script>/i, "") # NOT OK

  x = x.gsub(/<(script|del)(?=[\s>])[\w\W]*?<\/\1\s*>/i, "") # NOT OK
  x = x.gsub(/\<script[\s\S]*?\>[\s\S]*?\<\/script\>/, "") # NOT OK
  x = x.gsub(/<(script|style|title)[^<]+<\/(script|style|title)>/m, "") # NOT OK
  x = x.gsub(/<script[^>]*>([\s\S]*?)<\/script>/i, "") # NOT OK
  x = x.gsub(/<script[\s\S]*?<\/script>/i, "") # NOT OK
  x = x.gsub(/ ?<!-- ?/, "") # NOT OK
  x = x.gsub(/require\('\.\.\/common'\)/, "") # OK
  x = x.gsub(/\.\.\/\.\.\/lib\//, "") # OK

  # TODO: make Rubyish
  while x.include? "."
    x = x
      .gsub(/^\.\//, "")
      .gsub(/\/\.\//, "/")
      .gsub(/[^\/]*\/\.\.\//, "") # OK
  end

  x = x.gsub(/([^.\s]+\.)+/, "") # OK

  x = x.gsub(/<!\-\-DEVEL[\d\D]*?DEVEL\-\->/, "") # OK

  x = x
    .gsub(/^\.\//, "")
    .gsub(/\/\.\//, "/")
    .gsub(/[^\/]*\/\.\.\//, "") # NOT OK

  x
end

def m(content) 
	content.gsub(/<script.*\/script>/i, "") # NOT OK
	content.gsub(/<(script).*\/script>/i, "") # NOT OK
	content.gsub(/.+<(script).*\/script>/i, "") # NOT OK
	content.gsub(/.*<(script).*\/script>/i, "") # NOT OK
end

def m(content)
  content = content.gsub(/<script[\s\S]*?<\/script>/i, "") # NOT OK
  content = content.gsub(/<[a-zA-Z\/](.|\n)*?>/, '') || ' ' # NOT OK
  content = content.gsub(/<(script|iframe|video)[\s\S]*?<\/(script|iframe|video)>/, '') # NOT OK
  content = content.gsub(/<(script|iframe|video)(.|\s)*?\/(script|iframe|video)>/, '') # NOT OK
  content = content.gsub(/<[^<]*>/, "") # OK
end