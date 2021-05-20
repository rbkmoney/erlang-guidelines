# Инструментарий для разработки

## Редакторы

### IntelliJ IDEA + Erlang плагин

Идея поддерживает разработку на Erlang с помощью [соответствующего плагина](https://github.com/ignatov/intellij-erlang).

С деталями можно ознакомиться здесь: <https://www.jetbrains.com/help/idea/getting-started-with-erlang.html>

### Любой редактор + ErlangLS

Для разработки в редакторе, отличным от IntelliJ IDEA рекомендуется интеграция и использование [`erlang_ls`](https://github.com/erlang-ls/erlang_ls).

Конфигуририрование редактора для работы с `erlang_ls` изложено в секции "Editors" [на официальном сайте `erlang_ls`](https://erlang-ls.github.io/configuration/).

Детали конфигурирования самого `erlang_ls` можно найти по ссылке:  <https://erlang-ls.github.io/configuration/>.

Пример конфигурации (для проектов с `rebar3`):
```yaml
apps_dirs:
- "apps/*"
deps_dirs:
- "_build/default/lib/*"
- "_build/test/lib/*"
include_dirs:
- "include"
- "apps"
- "apps/*/include"
- "_build/*/lib/"
- "_build/*/lib/*/include"
```
