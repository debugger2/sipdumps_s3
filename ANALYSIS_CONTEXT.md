# Контекст задачи (pcap_merge)

Дата: 2026-10-22
Рабочая директория: C:\GIT\pcap_merge\

## Исходные данные
- W:\BACKUPS_others\naga_pcap\ - дампы операторской площадки:
  - smart_naga_fs09..fs14, fs17, fs19..fs22_dump2110.pcap (linktype 276, SLL2? Фреймы Ethernet в заголовке; анализ build_calls/make_flows)
  - smart_naga_klb01_dump2110.pcap, smart_naga_klb02_dump2110.pcap
  - smarted_naga_calls_161026.pcap
- C:\GIT\pcap_merge\smarted_naga_calls_161026_fs14.pcap, export_bd106201-440f-1240-b4bd-00505692fa7c_naga1.pcap
- C:\GIT\pcap_merge\analysis\sip_index.json (109MB) - индекс SIP со всех дампов

## Анализ/скрипты (analysis/)
- index_sip.py - построение sip_index.json
- find_calls.py - поиск диалогов с признаком оператора (181/178, X-icc_uuid)
- check_clock.py - сверка часов fs <-> klb
- build_calls.py - сборка merged_calls по X-icc_uuid: из fs берёт SIP+RTP, из klb добавляет SIP; буферизует все пакеты в память, сортирует по времени, пишет один pcap на вызов. Фильтр по медиа-портам и окну t0-3..t1+8, статистика fwd/rev/voice/loss/dup. Безголосые удаляются.
- verify.py - сверка пакетов src vs merged
- analyze_rtp.py - распаковка RTP в WAV
- make_flows.py - sngrep-стиль flow: слева тайминг/стрелки/метки между колонками участников, справа raw SIP каждого сообщения; в конце tshark -z rtp,streams. Парсинг SIP из UDP, поддержка фрагментации IP (собирает фрагменты по (src,dst,ident), но в этих дампах продолжения MF=0 off!=0 не находились -> TRUNCATED)
- audio/*.wav

## Результат
- W:\BACKUPS_others\naga_pcap\merged_calls\ - 13 merged pcap (12 из которых voice), по ~65KB..~11MB
- W:\BACKUPS_others\naga_pcap\merged_calls\*_flow.txt - 12 файлов, sngrep-стиль

## Сборка pcap из SIP-экспорта + записи FS (2026-10-25)
- analysis/build_from_recording.py <sip.pcap> <rec.mp3> [out] [--offset s] [--onset s]
  - SIP-only экспорт Homer + стерео-запись FreeSWITCH (L = исходящий FS->remote, R = входящий)
  - RTP синтезируется: адреса/порты/кодек из SDP offer/answer (PCMU/PCMA), ptime 20, mp3 t=0 = время INVITE
  - исходящий поток стартует с 18x/200 с SDP, входящий - с первого ненулевого сэмпла R после 18x (до этого в R локальный тон FS)
  - ffmpeg: C:\GIT\pcap_merge\tools\ffmpeg.exe (из imageio-ffmpeg; путь в профиле с кириллицей не работает)
- new\export_71374922-..._full.pcap: 10 SIP + 75539 RTP, оба потока setup by SDP, корреляция с mp3 0.9999. BYE в экспорте нет.

## Дампы из S3 (2026-11-10): s3_call_dump.py
- Бакеты: s3://icc-klb-call-dumps (SIP-прокси 51.38.198.88/89, с 2026-11-09 ~20:00),
  s3://icc-pbx-call-dumps (FreeSWITCH 137.74.249.148/149, SIP+RTP, с 2026-10-29).
  Ключ: <host-ip>/YYYY/MM/DD/YYYY-MM-DD_HH-MM-SS.pcap.gz (старые - без папок дат), имя = UTC старт ротации ~3 мин.
- Запуск там, где есть AWS-креды (Debian WSL): --from/--to (UTC или +HH:MM), --list | --all | --call-id/--icc-uuid/--number/--ip.
  Окно само расширяется (до --max-extend мин) до INVITE и BYE найденного звонка; плечи B2BUA связываются по X-*uuid.
  RTP берётся по SDP (ip:port и +1 для RTCP), дубли одного пакета с двух хостов удаляются (окно 0.5с).
  Кэш распакованных дампов: s3cache/, результат: calls/.
- Наблюдения: продолжения IP-фрагментов в дампах отсутствуют (фильтр tcpdump по udp port режет фрагменты без UDP-заголовка);
  у части звонков на pbx нет INVITE в дампе (сигнализация не по UDP), есть только RTP / BYE.

## Ключевые исправления
1. make_flows.py - фикс бага с рисованием заголовков/меток (list assignment out of range), метка не должна разрезаться колонками
2. build_calls.py - **главный фикс**: пакеты раньше писались по порядку сканирования файлов (сначала все fs-файлы, потом klb) -> merged-pcap был неотсортирован по времени. Wireshark VoIP Calls/Flow Sequence создаёт flow только на первом INVITE, пакеты раньше отбрасывались. Теперь буферизация + сортировка всех пакетов по (ts) перед записью. Устранило ситуацию, когда 141.94.5.146 (первый INVITE) оказывался в середине/после и не отображался в Wireshark flow.
