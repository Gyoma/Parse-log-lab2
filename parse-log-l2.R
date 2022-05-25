require('plyr')

args = commandArgs(trailingOnly = TRUE)

if (length(args) != 1)
  stop('You have to pass 1 argument which is a log file to inspect')

data = readLines(args[1])

is.regrule.followed = function(reg, str) {
  return (grepl(reg, str))
}

is.ipv4 = function(str) {
  return (is.regrule.followed('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', str))
}

#часть 1

# извлекаем потенциальные ip адреса
ip = sapply(data, function (row) sub(' - - (.*)', '', row), USE.NAMES = FALSE)

# отфильтровываем ip
ip = ip[is.ipv4(ip)]

# выводим 10 самых популярных

cat("\n10 most popular ip addresses:\n")

data.frame(sort(table(ip), decreasing = TRUE)[1:10])

#часть 2

is.regrule1.followed = function(str) { return (is.regrule.followed('((Windows NT 5.1)(.*)(rv:))|(Macintosh)|(Intel)', str)) }
is.regrule2.followed = function(str) { return (is.regrule.followed('Python-urllib/2..', str)) }
is.regrule3.followed = function(str) { return (is.regrule.followed('(HTTP/1.1)(.*)(WEBDAV|MSIE 8.0|Telesphoreo)', str)) }
is.regrule4.followed = function(str) { return (is.regrule.followed('(\\x[0-9A-Z][0-9A-Z]){2,}', str)) }
is.regrule5.followed = function(str) { return (is.regrule.followed('(GET|POST|HEAD|PROPFIND|OPTIONS)(.*)(499 0 "-")', str)) }

ip.df = data.frame(ip, ip.raw = data, violation.count = rep(0, length(ip)), stringsAsFactors = FALSE)

# обработка каждой строки
ip.df = adply(ip.df, 1, function (row) {
  if (is.regrule1.followed(row$ip.raw))
    row$violation.count = row$violation.count + 1
  
  if (is.regrule2.followed(row$ip.raw))
    row$violation.count = row$violation.count + 1
  
  if (is.regrule3.followed(row$ip.raw))
    row$violation.count = row$violation.count + 1
  
  if (is.regrule4.followed(row$ip.raw))
    row$violation.count = row$violation.count + 1
  
  if (is.regrule5.followed(row$ip.raw))
    row$violation.count = row$violation.count + 1
  
  return (row)
})

cat("\nSuspicious requests:\n")

# вывод подозрительных запросов
ip.df[ip.df$violation.count > 1, ]$ip.raw

