---
title: Wireshark 패킷 분석
parent: SIEM / 보안관제 프로젝트
nav_order: 3
---

# Wireshark 패킷 분석

포트 스캔, Brute Force, SQL Injection, SYN Flood, HTTP beacon 통신을 VM에서 직접 재현하고 대상 서버의 Wireshark에서 패킷을 분석한 실습 프로젝트다.

---


## 실습 환경

| 구분 | 구성 |
|---|---|
| 가상화 | Arch Linux, KVM / QEMU |
| 공격자 | Kali Linux `192.168.122.96` |
| 대상 | Debian `192.168.122.234` |
| SYN Flood | Mininet 호스트 100개 -> Debian `10.0.0.254` |

패킷은 모두 Debian에서 캡처했다. 마지막 beacon 실습에서는 Debian이 Kali의 HTTP 서버로 접속하도록 방향을 바꿨다.

![대상 서버 IP와 포트](/assets/images/packet/00-victim-environment.png)

대상에는 SSH 22번과 HTTP 80번 포트가 열려 있다.

---

## 시나리오 1 - TCP SYN 포트 스캔

Kali에서 대상의 1~1024번 TCP 포트를 스캔했다.

```bash
sudo nmap -sS -p 1-1024 --reason 192.168.122.234
```

![Nmap 포트 스캔](/assets/images/packet/01-portscan.png)

22번과 80번이 `open`으로 나왔다. `--reason`으로 열린 포트의 판정 근거가 `syn-ack`, 닫힌 포트는 `reset`인 것도 확인했다.

### 패킷 분석

서버의 SYN/ACK 응답을 제외하고 연결을 시작하는 SYN 패킷만 확인했다.

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

![SYN 패킷 필터](/assets/images/packet/02-wireshark-filter.png)

출발지 IP와 포트는 `192.168.122.96:61607`로 같지만 목적지 포트가 계속 바뀐다. 서로 다른 목적지 포트 1024개에 SYN이 하나씩 전송된 것을 확인했다.

열린 80번 포트를 보면 다음과 같다.

![80번 포트 응답](/assets/images/packet/03-wireshark-port-filter.png)

| 패킷 번호 | 방향 | 플래그 |
|---|---|---|
| 5 | Kali -> Debian | SYN |
| 13 | Debian -> Kali | SYN, ACK |
| 21 | Kali -> Debian | RST |

Debian이 SYN/ACK으로 응답하자 Kali 쪽에서 RST가 돌아왔다. 연결을 완성하는 ACK 없이 포트가 열려 있다는 사실만 확인하고 끝나는 SYN 스캔의 흐름이다.

닫힌 143번 포트의 응답은 다르다.

![143번 포트 응답](/assets/images/packet/04-wireshark-port143-filter.png)

1번 SYN에 대해 3번 RST/ACK이 바로 돌아온다. 전체 캡처에서도 SYN 1024개에 대해 RST/ACK 1022개와 SYN/ACK 2개가 확인되어 Nmap 결과와 일치했다.

**탐지 포인트**

- 한 출발지에서 짧은 시간에 여러 목적지 포트로 SYN을 전송하는지 확인한다.
- 연결 완료 여부와 대상의 응답을 함께 본다. 승인된 점검 서버의 스캔인지도 구분해야 한다.

---

## 시나리오 2 - 웹 로그인 Brute Force

DVWA에 로그인한 세션으로 내부 Brute Force 페이지를 테스트했다. 브루트포스 요청을 보내기 전에 비밀번호를 틀린 경우와 맞은 경우의 응답을 비교했다.

![로그인 실패](/assets/images/packet/10-login.png)

실패하면 `Username and/or password incorrect.`가 출력된다.

![로그인 성공](/assets/images/packet/11-login-success.png)

`admin / password`를 입력하면 `Welcome to the password protected area admin`이 나온다.

Hydra로 admin 계정에 비밀번호 후보 10개를 하나씩 시도했다. 응답에 Welcome to the password protected area가 포함되면 성공으로 판단하도록 설정했다.

### 패킷 분석

먼저 해당 페이지와 관련된 패킷을 확인했다.

```text
http.request.uri contains "/dvwa/vulnerabilities/brute/"
```

![Brute Force 페이지 관련 패킷](/assets/images/packet/13-wireshark-uri.png)

Hydra의 요청이 보인다.

![브루트 포스 응답](/assets/images/packet/14-wireshark-uri.png)

Hydra의 첫 비밀번호 시도인 40번 이후로 범위를 좁히고 요청 수를 세기 위해 `http.request` 조건을 추가했다.

```text
frame.number >= 40 && http.request && http.request.uri contains "username=admin"
```

계정은 같고 `password` 값만 바뀌는 요청이 10개다. 첫 요청부터 마지막 요청까지 약 1.8초가 걸렸고 9회 실패한 뒤 마지막 `password`에서 성공했다.

![실패 응답](/assets/images/packet/15-wireshark-tcp-stream.png)

![성공 응답](/assets/images/packet/16-wireshark-tcp-stream2.png)

실패와 성공 모두 HTTP 상태 코드는 `200 OK`였다. 성공 여부는 Follow TCP Stream의 응답 본문에서 `incorrect`와 `Welcome` 메시지를 비교해 확인했다.
응답 길이에도 차이가 있다.

**탐지 포인트**

- 같은 계정에 비밀번호만 바꿔 반복 요청하는 패턴을 확인한다.
- HTTP 200만으로 로그인 성공을 판단하지 않고 응답 본문과 로그를 확인한다.

---

## 시나리오 3 - SQL Injection

DVWA SQL Injection 페이지에서 정상 입력 `1`과 다음 입력의 결과를 비교했다.

```sql
1' OR '1'='1
```

![SQL Injection 실행 결과](/assets/images/packet/20-sqli.png)

악성 쿼리 입력에서는 `admin`, `Gordon`, `Hack`, `Pablo`, `Bob` 다섯 명의 정보가 출력됐다.


### 패킷 분석

```text
http.request && http.request.uri contains "/sqli/"
```

![SQL Injection 요청 필터링](/assets/images/packet/21-sqli-wireshark.png)

4번과 42번은 정상 요청이고 75번은 공격 요청이다. 공격 URI에는 입력값이 URL 인코딩되어 기록됐다.

```text
/dvwa/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit
```

`%27`은 작은따옴표, `%3D`는 등호이고 이 폼 요청에서 `+`는 공백이다. 디코딩하면 입력한 공격 문자열이 나온다.

![SQL Injection 응답 본문](/assets/images/packet/22-sqli-wireshark2.png)

SQL injection 요청의 응답 본문에서 다섯 명의 이름과 성을 확인했다.

**탐지 포인트**

- 숫자를 받는 파라미터에 따옴표나 SQL 연산자가 들어가는지 확인한다.
- 인코딩된 요청을 디코딩하고 정상 응답과 비교한다. 실제 영향은 웹·애플리케이션·DB 로그로 추가 확인한다.

---

## 시나리오 4 - SYN Flood DDoS 실습

별도 네트워크에 Mininet 호스트 100개(`10.0.0.1`~`10.0.0.100`)를 구성해 Debian `10.0.0.254:80`으로 SYN을 보냈다.

```text
px jobs = [h.popen('hping3 -n -q -S -p 80 -i u10000 -c 1000 10.0.0.254') for h in net.hosts]
```

### 패킷 분석

먼저 정상 HTTP 접속을 비교 기준으로 만들었다.

![정상 TCP 연결과 HTTP 응답](/assets/images/packet/30-dos.png)

1~3번에서 SYN -> SYN/ACK -> ACK로 연결을 완성하고 4번 HTTP GET에 6번 `200 OK`가 돌아온다. 정상 통신은 1~10번 패킷에 기록됐다.

이후 대상의 80번 포트로 들어오는 SYN을 필터링했다.

```text
ip.dst == 10.0.0.254 && tcp.dstport == 80 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

![다수 송신원의 SYN 패킷](/assets/images/packet/31.wireshark-ddos.png)

출발지 IP는 바뀌지만 목적지는 10.0.0.254:80으로 같다.

![SYN 송신원과 수신 패킷 수](/assets/images/packet/32-pcappng.png)

필터에 잡힌 SYN 98544개에서 정상 접속의 SYN 한 개를 제외하면 공격 패킷은 98543개다. 집계할 때 위 필터에 `frame.number > 10`을 추가했다.

이번에는 연결 하나를 골랐다.

```text
ip.addr == 10.0.0.18 && ip.addr == 10.0.0.254 && tcp.port == 1302 && tcp.port == 80
```

![SYN/ACK 재전송](/assets/images/packet/33-ddos-filter.png)

189번 SYN에 190번 SYN/ACK이 돌아오지만 연결을 완성하는 ACK는 없다. 같은 SYN/ACK이 20324번, 60804번, 146372번에서 약 1초, 2초, 4초 간격으로 재전송된다.

![SYN 패킷 I/O Graph](/assets/images/packet/34-wireshark-graph.png)

I/O Graph에서도 약 10초 동안 초당 1만 개에 가까운 SYN이 집중된다.

**탐지 포인트**

- 특정 IP, 포트에 SYN이 집중되는지, 연결 실패율이 높은지 함께 본다.

---

## 시나리오 5 - HTTP beacon 통신

Debian에서 Kali의 HTTP 서버로 `GET /check`를 보내고 5초 쉬는 작업을 12회 반복했다. 주기적으로 서버에 접속하는 비콘 형태를 curl로 재현했다.

### 패킷 분석

```text
http.request && ip.dst == 192.168.122.96 && tcp.dstport == 8000
```

![주기적으로 반복되는 HTTP 요청](/assets/images/packet/40-beacon.png)

같은 목적지와 URI로 요청이 반복된다.

| 항목 | 결과 |
|---|---|
| HTTP 요청 | 12개 |
| 요청 간 평균 간격 | 약 5초 |
| 첫 요청부터 마지막 요청까지 | 약 55초 |


![HTTP 요청과 응답 내용](/assets/images/packet/41-wireshark.png)

Follow TCP Stream에서 `User-Agent: curl/8.14.1`과 `HTTP/1.0 200 OK`를 확인했다.

**탐지 포인트**

- 같은 목적지로 반복되는 요청의 간격, URI, 크기를 함께 확인한다.
- 통신을 만든 프로세스와 목적지를 조사해 정상 상태 확인과 악성 통신을 구분한다.
