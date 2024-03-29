# Структура и шаблоны проектов

Набор подходов и рекомендаций к структуре проектов различного типа и назначения и шаблонов этих проектов.

Предложенные шаблоны планируется постоянно развивать и дополнять общим для всех проектов функционалом и инструментарием, поэтому комментарии и в особенности PR по ним приветствуются с крайним радушием.

В качестве средства для сборки проекта, а также множества других задач, используется [rebar3](www.rebar3.org), который предъявляет довольно строгие требования к структуре приложений и соответствию этой структуры принципам [OTP](http://learnyousomeerlang.com/what-is-otp).

## Общее описание

Для проектов, предоставляющих собой библиотеки или встраиваемые приложения, предлагается следующая минимальная структура:

```
  doc (optional)
  ├── index.md
  └── ...
  src
  ├── lib.app.src
  └── ...
  test
  └── ...
  Makefile
  README.md
  rebar.config
  wercker.yml
```

> Легко заметить, что предлагаемая структура располагает к написанию тестовых сценариев и документации.
>
> Документация помечена как _опциональная_, потому что в случае такого рода проектов часто достаточно встроенной непосредственно в исходники документации, например, посредством [спеков][1] и [edoc][2]-комментариев.

Для проектов, представляющих собой реализации полноценных боеспособных сервисов, предлагается следующая, во многом похожая структура:

```
  apps
  └── ...
  config
  ├── sys.config
  ├── vm.args
  └── ...
  doc
  ├── index.md
  └── ...
  Makefile
  README.md
  rebar.config
  wercker.yml
```

> В этом случае наличие документации обязательно, потому как в ней непременно должно фигурировать описание того, как _устанавливать_ и, что пожалуй даже более важно, _настраивать_ предложенный сервис. Однако это не отменяет возможность написания всё тех же [спеков][1] и [edoc][2]-комментариев.

В качестве основы рекомендуется использовать [шаблоны из erlang-templates](https://github.com/rbkmoney/erlang-templates):
- `erlang-service`: полноценный, но абсолютно ничего не делающий сервис со сборкой на внутреннем Jenkins.
- `erlang-library`: заготовка для библиотеки со сборкой на Github Actions.

[1]: http://erlang.org/doc/reference_manual/typespec.html
[2]: http://erlang.org/doc/apps/edoc/chapter.html
