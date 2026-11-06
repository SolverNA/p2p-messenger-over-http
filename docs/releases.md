# Запуск из GitHub Release

Репозиторий: [SolverNA/p2p-messenger-over-http](https://github.com/SolverNA/p2p-messenger-over-http). Готовые сборки доступны в [GitHub Releases](https://github.com/SolverNA/p2p-messenger-over-http/releases).

## Linux и macOS

Одна команда в **интерактивном терминале**:

```sh
curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/SolverNA/p2p-messenger-over-http/main/scripts/run.sh | P2PMESSENGER_REPO=SolverNA/p2p-messenger-over-http sh -s -- --bootstrap /dns4/node.example.org/tcp/443/tls/ws/p2p/PEER_ID
```

Без ручного `--bootstrap` версия v0.2.3 и новее получает общий список `public-peers.txt`; пока он пуст, нужен свой публичный узел. Настройки ручного bootstrap сохраняются. Вместо `main` используйте настоящий основной branch, если он называется иначе. Для воспроизводимого запуска замените `main` на проверенный тег в URL скрипта и добавьте `P2PMESSENGER_VERSION=v0.2.3` рядом с `P2PMESSENGER_REPO`.

Скрипт определяет Linux/macOS и x86_64/arm64, скачивает бинарник и контрольные суммы по HTTPS, сверяет SHA-256, открывает TUI и удаляет временные файлы после выхода. Данные чата остаются в обычном профиле. Go и Node на компьютере пользователя не нужны; нужны `curl` и `sha256sum` либо `shasum` (обычно уже есть). При передаче скрипта через pipe ввод TUI открывается из `/dev/tty`.

Это запуск **без ручного скачивания**, но загрузка исполняемого файла всё равно происходит. Команда исполняет код владельца выбранного репозитория. Скрипт не отключает Gatekeeper/антивирус и не подписывает macOS-бинарник: ограничения ОС могут потребовать отдельного разрешения на запуск.

Можно сначала сохранить и прочитать запускающий скрипт:

```sh
curl -fL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/SolverNA/p2p-messenger-over-http/main/scripts/run.sh -o run.sh
P2PMESSENGER_REPO=SolverNA/p2p-messenger-over-http sh ./run.sh --help
```

## Windows x64

В PowerShell:

```powershell
$env:P2PMESSENGER_REPO='SolverNA/p2p-messenger-over-http'; $p=Join-Path $env:TEMP ('p2pmessenger-'+[guid]::NewGuid().ToString('N')+'.ps1'); try { Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/$env:P2PMESSENGER_REPO/main/scripts/run.ps1" -OutFile $p; & $p --bootstrap /dns4/node.example.org/tcp/443/tls/ws/p2p/PEER_ID } finally { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue }
```

Если политика PowerShell запрещает выполнение скачанного скрипта, сначала просмотрите файл и используйте разрешённый в вашей системе способ запуска. Глобальное ослабление политики не требуется для самого мессенджера: можно скачать проверенный `.exe` из релиза напрямую. Windows ARM64 пока не входит в набор релиза.

Для вставки в TUI Windows используйте F4. Свой ID копируется по F3; сообщение или ID можно выбрать по F5. Ctrl+C копирует, Ctrl+Q закрывает приложение. F7 включает выделение текста терминалом. [Полная таблица клавиш](../README.md#управление).

## Для сопровождающего проекта

Пакет релиза включает:

| Артефакт | Платформа |
|---|---|
| `p2pmessenger-linux-amd64` | Linux x86_64 |
| `p2pmessenger-linux-arm64` | Linux arm64 |
| `p2pmessenger-darwin-amd64` | macOS Intel |
| `p2pmessenger-darwin-arm64` | macOS Apple Silicon |
| `p2pmessenger-windows-amd64.exe` | Windows x64 |
| `p2pmessenger-vVERSION-source.tar.gz` | Исходники выбранного коммита |
| `run.sh`, `run.ps1`, `SHA256SUMS` | Запускающие скрипты и контрольные суммы |

Нужны Go из `go.mod`, Git и Node.js 24. Проверки перед релизом:

```sh
node scripts/audit-publication.mjs --history
node --test tests/publication.test.mjs
node docs/check-architecture.mjs
go vet ./...
go test -race ./...
```

После проверки и коммита изменений `node scripts/build-release.mjs v0.2.3` собирает пять бинарников и архив через `git archive HEAD`. Рабочее дерево должно быть чистым, а `dist/` — пустым. `-trimpath -buildvcs=false` убирают локальные пути компиляции и VCS-метаданные сборки; приватный профиль не участвует. Архив содержит весь проверенный коммит, включая исходники, тесты и документацию. Проверка истории останавливает сборку при обнаружении конкретных IP, Peer ID, профилей и других отмечаемых данных; публичное авторство коммитов разрешено.

Workflow `.github/workflows/release.yml` срабатывает на push тега `v0.2.3`, запускает проверки и создаёт **черновик** GitHub Release. Исходники уже должны быть обезличены до первого push: проверка Actions не может отменить их загрузку на GitHub. После просмотра артефактов опубликуйте черновик; только тогда начинает работать `/releases/latest/download`. Для prerelease задавайте конкретную версию. [Документация `gh release create`](https://cli.github.com/manual/gh_release_create).

Не пушьте личные ветки/теги с прежними данными при подготовке чистой публикации. Если нужна отдельная чистая история, создайте её в отдельном каталоге после согласования обезличивания. Нельзя просто удалить строку в последнем коммите и считать прежние коммиты очищенными. Перед публичным распространением также выберите лицензию: этот репозиторий пока не назначает разрешительную лицензию автоматически.
