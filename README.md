# Error Analytics - 로그 에러 분석 도구

서버 로그 파일에서 에러를 자동으로 집계하여 CSV 리포트를 생성하는 Python 스크립트입니다.
PG(변환 서버)와 SD(StreamDocs 뷰어 서버) 두 가지 분석을 지원합니다.

## 디렉토리 구조

```
error_analytics/
├── analyze_errors.py       # PG 로그 분석 스크립트
├── analyze_sd_errors.py    # SD 로그 분석 스크립트
├── error_codes.py          # PG 에러코드 → 설명 매핑 사전
├── pg/                     # PG 로그 디렉토리
│   ├── 1/ … 6/            # 서버별 폴더
│   └── error_report_by_date_*.csv
├── sd/                     # SD 로그 디렉토리
│   ├── 1/ … 5/            # 서버별 폴더
│   │   ├── sd.2026-04-01.0.log
│   │   └── access/
│   │       └── access_20260401.log
│   └── sd_error_report_by_date_*.csv
└── README.md
```

## 요구사항

- Python 3.10 이상 (표준 라이브러리만 사용, 별도 패키지 설치 불필요)

---

## 1. PG 로그 분석 (`analyze_errors.py`)

PG 서버 로그에서 작업(Job) 성공/실패 현황, 에러코드, TSA-GPKI 에러를 집계합니다.

### 로그 파일 배치

`pg/` 하위에 서버별 폴더를 만들고 `pg.log.YYYY-MM-DD.N.log` 형식의 파일을 넣습니다.

### 실행

```bash
python analyze_errors.py
```

### CSV 컬럼 구성

| 컬럼 | 설명 |
|------|------|
| 파일명 (또는 날짜) | 로그 파일명 또는 날짜 |
| 전체작업 | Finished Job 총 건수 |
| 성공 | SUCCESS 건수 |
| 실패 | FAILURE 총 건수 |
| 변환 실패 | 실패 - TSA 실패 (순수 변환 실패 건수) |
| TSA 실패 | GPKI 관련 실패 건수 |
| 전체 실패율(%) | 실패 / 전체작업 |
| 변환 실패율(%) | 변환 실패 / 전체작업 |
| TSA 실패율(%) | TSA 실패 / 전체작업 |
| 에러코드별 컬럼 | 각 에러코드의 발생 건수 |
| 실패합계 | 에러코드 건수 합계 |
| [TSA] 메시지별 컬럼 | GPKI 에러 메시지별 발생 건수 |



## 에러코드 사전 (PG)

`error_codes.py`에 PG 에러코드와 설명이 매핑되어 있습니다.

```python
ERROR_CODES: dict[str, str] = {
    "BEP000000": "서비스 구동에 실패했습니다",
    "BEP010000": "서비스 초기화에 실패했습니다",
    ...
}
```


---

## 2. SD 로그 분석 (`analyze_sd_errors.py`)

SD(StreamDocs) 서버 로그의 ERROR 레벨 이벤트와 access 로그의 HTTP 상태 코드를 통합 분석합니다.

### 로그 파일 배치

```
sd/
├── 1/
│   ├── sd.2026-04-01.0.log      # 서버 로그
│   ├── sd.2026-04-01.1.log      # 같은 날짜 로테이션 파일
│   └── access/
│       └── access_20260401.log  # access 로그
├── 2/
│   └── ...
```

- 서버 로그: `sd.YYYY-MM-DD.N.log` 형식
- Access 로그: `access_YYYYMMDD.log` 형식 (`access/` 하위 폴더)

### 실행

```bash
python analyze_sd_errors.py
```

### 출력 파일

| 파일 | 위치 | 설명 |
|------|------|------|
| `sd_error_report_server{N}_*.csv` | `sd/{N}/` | 서버별 날짜별 리포트 |
| `sd_error_report_by_date_*.csv` | `sd/` | 전체 서버 날짜별 통합 리포트 |

### CSV 컬럼 구성

| 컬럼 | 설명 |
|------|------|
| 날짜 | 분석 대상 날짜 |
| 전체 요청 | 성공 + HTTP 500 |
| 성공(HTTP 200/201) | access 로그의 2xx 응답 건수 |
| HTTP 500 | access 로그의 500 응답 건수 |
| 서버 ERROR 합계 | 서버 로그에서 분류된 ERROR 이벤트 총 건수 |
| WAS/프록시 에러 | HTTP 500 중 서버 로그에 ERROR가 없는 건수 |
| 에러 카테고리별 컬럼 | 각 분류별 발생 건수 (아래 참조) |

마지막 행에 합계와 전체 요청 대비 비율(%)이 출력됩니다.

### 에러 분류 체계

| 분류 | 설명 |
|------|------|
| **[ExceptionCode] FARGRS** | 리소스 등록 실패 (ORA-00001 + FARGRS 쌍) |
| **[Viewer] error-code 계열** | pdfio 렌더링 에러 (`RENDERTOJPEG_FAILURE`, `LOADCONTENTS_FAILURE` 등) |
| **[Viewer] 이미지 생성 실패** | 페이지 이미지 생성 실패 |
| **[Viewer] 캐시로 인해 삭제된 문서 조회** | 이미 삭제된 문서 ID 조회 |
| **[Controller] pdfio 실행 실패** | pdfio 프로세스 실행 실패 |
| **[PKI] VID 검증 실패(본인확인 실패)** | VIDCheck + 본인확인 실패 쌍 |
| **[PKI] 서명 데이터/파일 생성 실패** | PKI 서명 처리 에러 체인 |
| **[TSA] 검증 실패** | TSA 타임스탬프 검증 에러 체인 |
| **WAS/프록시 에러** | 서버 로그에 미기록된 HTTP 500 (프록시 레벨) |

### 에러 중복 카운트 방지 로직

SD 분석은 하나의 HTTP 요청에서 여러 ERROR가 연쇄 발생하는 경우를 1건으로 처리합니다.

- **ORA + FARGRS 쌍**: ORA-00001과 뒤따르는 ExceptionCode FARGRS를 1건으로 집계. 제약조건 키를 학습하여 동일 키 재발생 시 자동 매칭.
- **PKI 에러 체인**: `CustomPKIManager` → `CustomPdfController` 연쇄를 스레드 ID 기반으로 1건 처리.
- **TSA 에러 체인**: `DefaultHttpTsaSigner` → `CustomTSAManager` → `StreamdocsExceptionHandler` 연쇄를 1건 처리.
- **VID 검증 쌍**: `CustomPKIManager`의 VIDCheck + `CustomPdfController`의 본인확인 실패를 1건 처리.
- **비-ORA DB 에러**: `SqlExceptionHelper`의 소켓/연결 에러는 후속 핸들러에서 처리되므로 무시.
- **TransactionInterceptor**: 트랜잭션 롤백 이차 에러 무시.
- **시스템 파일 에러**: `FileUtils` 정리 에러는 HTTP 응답에 무관하므로 제외.
