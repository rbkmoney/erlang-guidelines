# Введение

*XML eXternal Entity injection* (XXE) - атака на приложение, которое анализирует ввод XML. XXE занимает категорию А4 в списке уязвимостей [OWASP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project).
Эта атака возможна из-за обработки синтаксическим анализатором XML непроверенных данных, содержащих ссылку на внешнюю сущность.

Возможные последствия:
- чтение локальных файлов сервера; 
- отказ в обслуживании; 
- [подделка запросов на стороне сервера ](https://www.owasp.org/index.php/Server_Side_Request_Forgery) (SSRF); 
- сканирование портов в сети с машины, на которой находится анализатор; 
- и другим системным воздействиям.

Данное руководство содержит краткую информацию для предотвращения этой уязвимости.
Подробнее можно ознакомиться здесь: [XML External Entity (XXE)](https://en.wikipedia.org/wiki/XML_external_entity_attack).

# Демонстрация атаки

В стандартном XML-парсере xmerl по умолчанию разрешены внешние сущности, что позволяет читать локальные файлы или вызвать отказ в обслуживании сервиса. 

Пример уязвимого кода:
```
#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable -sname factorial -mnesia debug verbose
main([Path]) ->
    try
        io:format("Xml file path[~p]~n", [Path]),
        Xml = xmerl_scan:file(Path),
        {ok, Dir} = file:get_cwd(),
        Format = io_lib:format("~p", [Xml]),
        ok = file:write_file(Dir ++ "/xml.out", Format, [append])
    catch
        Excep:Error:St ->
            io:format("~p: ~n ~p~n~p", [Excep, Error, St]),
            halt(1)
    end;
main(_) ->
    halt(1).
```

Пример вредоносной нагрузки на чтение локальных файлов:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<response>
	<result>&xxe;</result>
</response>
```

Пример вредоносной нагрузки на отказ в обслуживании сервиса:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///dev/zero" >]>
<response>
	<result>&xxe;</result>
</response>
```
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe "XXE" >
<!ENTITY xxe2 "&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;" >
<!ENTITY xxe3 "&xxe2;&xxe2;&xxe2;&xxe2;&xxe2;&xxe2;&xxe2;&xxe2;&xxe2;&xxe2;" >
<!ENTITY xxe4 "&xxe3;&xxe3;&xxe3;&xxe3;&xxe3;&xxe3;&xxe3;&xxe3;&xxe3;&xxe3;" >
<!ENTITY xxe5 "&xxe4;&xxe4;&xxe4;&xxe4;&xxe4;&xxe4;&xxe4;&xxe4;&xxe4;&xxe4;" >
<!ENTITY xxe6 "&xxe5;&xxe5;&xxe5;&xxe5;&xxe5;&xxe5;&xxe5;&xxe5;&xxe5;&xxe5;" >
<!ENTITY xxe7 "&xxe6;&xxe6;&xxe6;&xxe6;&xxe6;&xxe6;&xxe6;&xxe6;&xxe6;&xxe6;" >
<!ENTITY xxe8 "&xxe7;&xxe7;&xxe7;&xxe7;&xxe7;&xxe7;&xxe7;&xxe7;&xxe7;&xxe7;" >
<!ENTITY xxe9 "&xxe8;&xxe8;&xxe8;&xxe8;&xxe8;&xxe8;&xxe8;&xxe8;&xxe8;&xxe8;" >
]>
<response>
	<result>&xxe9;</result>
</response>
```

# Общие рекомендации

Самый безопасный способ предотвратить XXE - полностью отключить DTD (внешние сущности)
Если невозможно полностью отключить DTD, то внешние сущности и объявления типа внешнего документа должны быть отключены способом, специфичным для каждого анализатора.

# Безопасный пример для xmerl

В стандартном парсере xmerl по умолчанию разрешены внешние сущности. Чтобы их запретить, необходимо использовать опции `{acc_fun, Fun}` и `{fetch_fun, Fun}`

Пример безопасного парсера:
```
#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable -sname factorial -mnesia debug verbose
main([Path]) ->
    try
        io:format("Xml file path[~p]~n", [Path]),
        Fun = fun(_, GlobalState) ->                    %% deny to fetch an external resource (e.g. a DTD).
            throw(contain_entity),
            {ok, {string, "not_fetched"}, GlobalState}
        end,

        FunAcc = fun
            (ParsedEntity, Acc, GlobalState) ->
                case xmerl_scan:user_state(GlobalState) of
                    N when N > 5 -> throw(too_mach_items);      %% deny a big file
                    N ->
                        {[ParsedEntity | Acc], xmerl_scan:user_state(N+1, GlobalState)}
                end
        end,

        RulesState = #{rules => []},

        FunRuleRead = fun(Context, Name, ScannerState) ->
            throw(contain_entity)   %% deny process any <!ENTITY ... >
        end,

        FunRuleWrite = fun(Context, Name, Definition, ScannerState) ->
            throw(contain_entity)   %% deny process any <!ENTITY ... >
        end,

        Xml = xmerl_scan:file(Path, [
            {user_state, 0},
            {fetch_fun, Fun},
            {acc_fun, FunAcc},
            {rules, FunRuleRead, FunRuleWrite, RulesState}
        ]),
        {ok, Dir} = file:get_cwd(),
        Format = io_lib:format("~p", [Xml]),
        ok = file:write_file(Dir ++ "/xml.out", Format, [append])
    catch
        Excep:Error:St ->
            io:format("Error ~p: ~n ~p~n~p", [Excep, Error, St]),
            halt(1)
    end;
main(_) ->
    halt(1).
```

# Безопасный пример для erlsom

XML парсер [xmerl](https://github.com/willemdj/erlsom) возможно использовать в различных режимах. Для отключения внешних сущностей достаточно использовать его в режиме [SAX парсера](https://github.com/willemdj/erlsom#sax). 

rebar.config:
```
{erl_opts, [no_debug_info]}.
{deps, [
    {erlsom, "1.5.0"}
]}.

{escript_incl_apps,
 [parser]}.
{escript_main_app, parser}.
{escript_name, parser}.
{escript_emu_args, "%%! +sbtu +A1\n"}.

%% Profiles
{profiles, [{test,
             [{erl_opts, [debug_info]}
            ]}]}.
```

parser.erl:
```
-module(parser).

%% API exports
-export([main/1]).

%%====================================================================
%% API functions
%%====================================================================

%% escript Entry point
main([Path]) ->
    io:format("Open file: ~p~n", [Path]),
    Options = [{expand_entities, false}],
    io:format("Parse xml with options: ~p~n", [Options]),
    {ok, XmlBinary} = file:read_file(Path),
    {ok, Result, []} = erlsom:parse_sax(XmlBinary, [], fun(Event, Acc) ->
        % io:format("~p~n", [Event]),
        [Event|Acc]
    end, Options),
    Xml = lists:reverse(Result),
    {ok, Dir} = file:get_cwd(),
    ok = file:write_file(Dir ++ "/xml.out", io_lib:format("~p", [Xml]), [append]),
    erlang:halt(0).

%%====================================================================
%% Internal functions
%%====================================================================
```

parser.app.src:
```
{application, parser,
 [{description, "An escript"},
  {vsn, "0.1.0"},
  {registered, []},
  {applications,
   [kernel,
    stdlib,
    erlsom
   ]},
  {env,[]},
  {modules, []},

  {licenses, ["Apache 2.0"]},
  {links, []}
 ]}.
```

To build:
```
$ rebar3 escriptize [{escript_incl_apps, [erlsom]}]
```
To run:
```
$ _build/default/bin/parser "path/to/xml/file"
```

# References

- [XXE by InfoSecInstitute](https://resources.infosecinstitute.com/identify-mitigate-xxe-vulnerabilities/)
- [OWASP Top 10-2017 A4: XML External Entities (XXE)](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE))
- [Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"](https://vsecurity.com//download/papers/XMLDTDEntityAttacks.pdf)
- [FindSecBugs XXE Detection](https://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER)
- [XXEbugFind Tool](https://github.com/ssexxe/XXEBugFind)
- [Testing for XML Injection (OTG-INPVAL-008)](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
