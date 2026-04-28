"""SD(StreamDocs) 로그 파일의 ERROR 통계를 분석하여 CSV 리포트를 생성한다."""

import re
import os
import glob
import csv
from datetime import datetime
from collections import Counter, defaultdict

DEFAULT_LOG_DIR = os.path.join(os.path.dirname(__file__), "sd")
DEFAULT_LOG_PATTERN = "sd.*.log"
ACCESS_LOG_DIR = "access"
ACCESS_LOG_PATTERN = "access_*.log"
DATE_FROM_FILENAME_RE = re.compile(r"sd\.(\d{4}-\d{2}-\d{2})\.\d+\.log")
ACCESS_DATE_RE = re.compile(r"access_(\d{4})(\d{2})(\d{2})\.log")
ACCESS_STATUS_RE = re.compile(r'HTTP/1\.\d"\s+(\d{3})\s')

LOG_LINE_RE = re.compile(r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
THREAD_RE = re.compile(r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \[(.+?)\]")
ERROR_DETAIL_RE = re.compile(r"ERROR\s+(\S+)\s+-\s+(.*)")

ORA_LOGGER = "o.h.e.jdbc.spi.SqlExceptionHelper"
ORA_CONSTRAINT_KEY_RE = re.compile(r"\(\w+\.(\w+)\)")
EXCEPTION_CODE_INNER_RE = re.compile(r"ExceptionCode\s*:\s*(\S+)")
PDFIO_ERROR_CODE_RE = re.compile(r"error-code\s*:\s*(\S+)")
FARGRS_KEY = "[ExceptionCode] FARGRS (리소스 등록 실패)"

EXCEPTION_CODE_NAMES = {
    "FARGRS": "리소스 등록 실패",
}

# CSV에서 카테고리 정렬 순서를 제어하기 위한 접두사
CATEGORY_ORDER = [
    "[ExceptionCode]",
    "[DB]",
    "[Viewer]",
    "[Controller]",
    "[PKI]",
    "[TSA]",
    "[시스템]",
    "[기타]",
]


def classify_error(logger: str, message: str) -> str | None:
    """ERROR 로그를 카테고리 문자열로 분류한다. None이면 무시(중복 방지)."""

    # --- StreamdocsExceptionHandler ---
    if "StreamdocsExceptionHandler" in logger:
        if "Exception thrown at controller" in message:
            return None  # 후속 메시지와 항상 쌍으로 발생 → 후속 메시지만 카운트
        if "이미지 생성" in message:
            return "[Viewer] 이미지 생성 실패"
        if "RENDERTOJPEG" in message:
            return "[Viewer] RENDERTOJPEG 실패"
        if "LOADCONTENTS" in message:
            return "[Viewer] LOADCONTENTS 실패"
        if message.startswith("UNKNOWN"):
            return "[Viewer] UNKNOWN 에러"
        if "자료를 찾을 수 없습니다" in message:
            return "[Viewer] 캐시로 인해 삭제된 문서 조회"
        if "요청 처리 중 오류" in message:
            return "[Viewer] 요청 처리 오류"
        if "ARGUMENT" in message:
            return "[Viewer] ARGUMENT 에러"
        if "ZERO_BYTE" in message:
            return "[Viewer] ZERO_BYTE 출력"
        return f"[Viewer] {message[:60]}"

    # --- CustomPdfController (ExceptionCode/본인확인 제외 - 메인 루프에서 별도 처리) ---
    if "CustomPdfController" in logger:
        if "본인확인" in message:
            return "PAIR:VID"
        if "폐지된 인증서" in message:
            return "PAIR:PKI_FOLLOW:[Controller] 폐지된 인증서"
        if "만료된 인증서" in message:
            return "PAIR:PKI_FOLLOW:[Controller] 만료된 인증서"
        if "sign file" in message:
            return "PAIR:PKI_FOLLOW:[Controller] 서명 파일 생성 실패"
        if "pdfio failed" in message:
            return "[Controller] pdfio 실행 실패"
        if "PdfResource" in message and "empty" in message:
            return "[Controller] 빈 PdfResource"
        return f"PAIR:PKI_FOLLOW:[Controller] {message[:60]}"

    # --- CustomPKIManager ---
    if "CustomPKIManager" in logger:
        if "VIDCheck" in message:
            return "PAIR:VID_SOURCE"
        if "sign data" in message:
            return "PAIR:PKI:[PKI] 서명 데이터 생성 실패"
        if "sign file" in message:
            return "PAIR:PKI:[PKI] 서명 파일 생성 실패"
        if "만료" in message:
            return "PAIR:PKI:[PKI] 만료된 인증서 응답"
        if "Api return" in message:
            return "PAIR:PKI:[PKI] API 응답 오류"
        return f"PAIR:PKI:[PKI] {message[:60]}"

    # --- TSA ---
    if "CustomTSAManager" in logger:
        if "ConnectException" in message or "Connection refused" in message:
            return "PAIR:TSA:[TSA] 연결 거부"
        if "Timeout" in message or "timed out" in message:
            return "PAIR:TSA:[TSA] 타임아웃"
        return f"PAIR:TSA:[TSA] {message[:60]}"

    if "DefaultHttpTsaSigner" in logger:
        return "PAIR:TSA:[TSA] 검증 실패"

    # --- CustomPKIService ---
    if "CustomPKIService" in logger:
        return "[PKI] API 응답 오류"

    # --- 시스템 ---
    if "SchemaUpdate" in logger:
        return "[시스템] DDL 스키마 오류"
    if "FileUtils" in logger:
        return "[시스템] 파일 삭제 실패"

    return f"[기타] {logger}:{message[:40]}"


def _category_sort_key(cat: str) -> tuple:
    """CSV 열 정렬용 키. CATEGORY_ORDER 접두사 순서 → 카테고리명 알파벳순."""
    for idx, prefix in enumerate(CATEGORY_ORDER):
        if cat.startswith(prefix):
            return (idx, cat)
    return (len(CATEGORY_ORDER), cat)


def analyze_sd_log(log_path: str, fargrs_ora_keys: set | None = None) -> dict:
    """SD 로그 파일을 한 번 순회하며 모든 ERROR를 분류·집계한다.

    ORA+FARGRS 쌍에서 제약조건 키를 학습하고, 같은 키의 ORA 에러는
    FARGRS가 뒤따르지 않아도 FARGRS(리소스 등록 실패)로 카운트한다.
    """
    error_counts: Counter[str] = Counter()
    known_keys = fargrs_ora_keys if fargrs_ora_keys is not None else set()
    ora_fargrs_pending = 0      # ORA(학습된 키)로 이미 카운트한 수 (후속 FARGRS 차감용)
    pending_ora = False         # 미학습 키의 ORA 대기
    pending_ora_key: str | None = None
    pending_vid = False

    # 스레드 ID별로 "Exception thrown at controller" + error-code 추적
    pending_controllers: dict[str, str | None] = {}  # thread_id → error_code
    last_controller_thread: str | None = None  # 현재 스택 트레이스가 속한 스레드

    # PKI/TSA 에러 체인: 같은 스레드에서 연쇄 에러가 1건의 요청
    pending_chain_threads: set[str] = set()

    def _flush_pending():
        nonlocal pending_ora, pending_ora_key, pending_vid
        if pending_ora:
            error_counts["[DB] 단독 ORA 에러"] += 1
            pending_ora = False
            pending_ora_key = None
        if pending_vid:
            error_counts["[PKI] VID 검증 실패(본인확인 실패)"] += 1
            pending_vid = False

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not LOG_LINE_RE.match(line):
                if last_controller_thread and last_controller_thread in pending_controllers:
                    if pending_controllers[last_controller_thread] is None:
                        ec_m = PDFIO_ERROR_CODE_RE.search(line)
                        if ec_m:
                            pending_controllers[last_controller_thread] = ec_m.group(1)
                continue

            last_controller_thread = None

            m = ERROR_DETAIL_RE.search(line)
            if not m:
                continue

            logger = m.group(1)
            message = m.group(2).strip()

            # --- StreamdocsExceptionHandler: 스레드별 error-code 기반 분류 ---
            if "StreamdocsExceptionHandler" in logger:
                tm = THREAD_RE.match(line)
                tid = tm.group(1) if tm else ""

                if "Exception thrown at controller" in message:
                    pending_controllers[tid] = None
                    last_controller_thread = tid
                    continue

                if tid in pending_controllers:
                    ec = pending_controllers.pop(tid)
                    if tid in pending_chain_threads:
                        pending_chain_threads.discard(tid)
                        continue
                    if ec is not None:
                        error_counts[f"[Viewer] {ec}"] += 1
                    else:
                        category = classify_error(logger, message)
                        if category and not category.startswith("PAIR:"):
                            error_counts[category] += 1
                    continue

            # --- ORA DB 에러 (SqlExceptionHelper) ---
            if logger == ORA_LOGGER:
                if "ORA-" not in message:
                    continue
                key_m = ORA_CONSTRAINT_KEY_RE.search(message)
                ora_key = key_m.group(1) if key_m else None

                if ora_key and ora_key in known_keys:
                    error_counts[FARGRS_KEY] += 1
                    ora_fargrs_pending += 1
                else:
                    if pending_ora:
                        error_counts["[DB] 단독 ORA 에러"] += 1
                    pending_ora = True
                    pending_ora_key = ora_key
                continue

            # --- ExceptionCode (FARGRS 등) ---
            if "CustomPdfController" in logger:
                exc_m = EXCEPTION_CODE_INNER_RE.search(message)
                if exc_m:
                    code = exc_m.group(1)
                    if code == "FARGRS":
                        if pending_ora and pending_ora_key:
                            known_keys.add(pending_ora_key)
                            error_counts[FARGRS_KEY] += 1
                            pending_ora = False
                            pending_ora_key = None
                        elif ora_fargrs_pending > 0:
                            ora_fargrs_pending -= 1
                        else:
                            error_counts[FARGRS_KEY] += 1
                    else:
                        desc = EXCEPTION_CODE_NAMES.get(code, code)
                        error_counts[f"[ExceptionCode] {code} ({desc})"] += 1
                        pending_ora = False
                        pending_ora_key = None
                    continue

            # --- TransactionInterceptor: 롤백 시 이차 에러 (원본 예외는 별도 핸들러에서 처리) ---
            if "TransactionInterceptor" in logger:
                continue

            # --- 분류 ---
            category = classify_error(logger, message)
            if category is None:
                continue

            # --- VIDCheck + 본인확인실패 쌍 처리 ---
            if category == "PAIR:VID_SOURCE":
                if pending_vid:
                    error_counts["[PKI] VID 검증 실패(본인확인 실패)"] += 1
                pending_vid = True
                if pending_ora:
                    error_counts["[DB] 단독 ORA 에러"] += 1
                    pending_ora = False
                    pending_ora_key = None
                continue

            if category == "PAIR:VID":
                error_counts["[PKI] VID 검증 실패(본인확인 실패)"] += 1
                pending_vid = False
                if pending_ora:
                    error_counts["[DB] 단독 ORA 에러"] += 1
                    pending_ora = False
                    pending_ora_key = None
                continue

            # --- PKI 에러 체인 처리 (PKIManager → Controller = 1건) ---
            if category.startswith("PAIR:PKI:"):
                tm = THREAD_RE.match(line)
                tid = tm.group(1) if tm else ""
                if tid not in pending_chain_threads:
                    actual_cat = category[len("PAIR:PKI:"):]
                    error_counts[actual_cat] += 1
                    pending_chain_threads.add(tid)
                continue

            if category.startswith("PAIR:PKI_FOLLOW:"):
                tm = THREAD_RE.match(line)
                tid = tm.group(1) if tm else ""
                if tid in pending_chain_threads:
                    pending_chain_threads.discard(tid)
                else:
                    actual_cat = category[len("PAIR:PKI_FOLLOW:"):]
                    error_counts[actual_cat] += 1
                continue

            # --- TSA 에러 체인 (DefaultHttpTsaSigner → CustomTSAManager = 1건) ---
            if category.startswith("PAIR:TSA:"):
                tm = THREAD_RE.match(line)
                tid = tm.group(1) if tm else ""
                if tid not in pending_chain_threads:
                    actual_cat = category[len("PAIR:TSA:"):]
                    error_counts[actual_cat] += 1
                    pending_chain_threads.add(tid)
                continue

            # --- 일반 에러 ---
            tm = THREAD_RE.match(line)
            tid = tm.group(1) if tm else ""
            if category.startswith("[시스템]"):
                continue
            _flush_pending()
            pending_chain_threads.discard(tid)
            error_counts[category] += 1

    for tid, ec in pending_controllers.items():
        if ec is not None:
            error_counts[f"[Viewer] {ec}"] += 1
    pending_controllers.clear()
    _flush_pending()

    return {"error_counts": error_counts, "fargrs_ora_keys": known_keys}


def extract_date(filename: str) -> str:
    """파일명에서 날짜(YYYY-MM-DD)를 추출한다."""
    m = DATE_FROM_FILENAME_RE.search(filename)
    return m.group(1) if m else "unknown"


def extract_access_date(filename: str) -> str:
    """access 로그 파일명에서 날짜(YYYY-MM-DD)를 추출한다."""
    m = ACCESS_DATE_RE.search(filename)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    return "unknown"


def analyze_access_log(log_path: str) -> dict:
    """access 로그에서 HTTP 상태 코드별 건수를 집계한다.

    2xx → 성공, 5xx → HTTP 에러로 추출, 3xx/4xx → 무시
    """
    status_counts: Counter[str] = Counter()
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ACCESS_STATUS_RE.search(line)
            if m:
                status_counts[m.group(1)] += 1
    success = sum(cnt for code, cnt in status_counts.items() if code.startswith("2"))
    http_errors: Counter[str] = Counter()
    for code, cnt in status_counts.items():
        if code.startswith("5"):
            http_errors[f"HTTP {code}"] = cnt
    return {"success": success, "http_errors": http_errors}


def build_access_map(server_dir: str) -> dict[str, dict]:
    """서버 폴더 내 access 로그를 분석하여 {날짜: {success, http_errors}} 맵을 반환한다."""
    access_dir = os.path.join(server_dir, ACCESS_LOG_DIR)
    if not os.path.isdir(access_dir):
        return {}

    access_files = sorted(glob.glob(os.path.join(access_dir, ACCESS_LOG_PATTERN)))
    date_map: dict[str, dict] = {}

    for af in access_files:
        fname = os.path.basename(af)
        date_str = extract_access_date(fname)
        if date_str == "unknown":
            continue
        result = analyze_access_log(af)
        if date_str in date_map:
            date_map[date_str]["success"] += result["success"]
            date_map[date_str]["http_errors"].update(result["http_errors"])
        else:
            date_map[date_str] = result

        err_str = ", ".join(f"{c}={n:,}" for c, n in result["http_errors"].most_common(3))
        print(f"    [access] {fname}: 성공 {result['success']:,}건"
              + (f" / {err_str}" if err_str else ""))

    return date_map


def write_sd_result(
    per_file_data: list[dict],
    total_counts: Counter,
    output_path: str,
    row_label: str = "파일명",
    total_success: int = 0,
    total_http_errors: Counter | None = None,
) -> None:
    """파일별(또는 날짜별) ERROR 카운트 및 전체 요약을 CSV 결과 파일로 저장한다."""
    all_cats = sorted(total_counts.keys(), key=_category_sort_key)
    has_access = any(d.get("success_count", 0) > 0 for d in per_file_data)

    http_err_cols: list[str] = []
    if total_http_errors:
        http_err_cols = sorted(total_http_errors.keys())

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        header = [row_label]
        if has_access:
            header += ["전체 요청", "성공(HTTP 200/201)"]
        header += http_err_cols + ["서버 ERROR 합계"]
        if http_err_cols:
            header += ["WAS/프록시 에러 (ex. malformed URL 요청)"]
        header += all_cats
        writer.writerow(header)

        for d in per_file_data:
            row = [d["file"]]
            d_http = d.get("http_errors", {})
            d_success = d.get("success_count", 0)
            d_http500 = d_http.get("HTTP 500", 0) if d_http else 0
            if has_access:
                row += [d_success + d_http500, d_success]
            for col in http_err_cols:
                row.append(d_http.get(col, 0) if d_http else 0)
            row_total = sum(d["error_counts"].get(cat, 0) for cat in all_cats)
            row.append(row_total)
            if http_err_cols:
                row.append(max(d_http500 - row_total, 0))
            for cat in all_cats:
                row.append(d["error_counts"].get(cat, 0))
            writer.writerow(row)

        writer.writerow([])
        total_http500 = 0
        for col in http_err_cols:
            if col == "HTTP 500":
                total_http500 = total_http_errors.get(col, 0) if total_http_errors else 0
        grand = sum(total_counts[cat] for cat in all_cats)
        total_requests = total_success + total_http500

        summary = ["[합계]"]
        if has_access:
            summary += [total_requests, total_success]
        for col in http_err_cols:
            summary.append(total_http_errors[col] if total_http_errors else 0)
        summary.append(grand)
        if http_err_cols:
            summary.append(max(total_http500 - grand, 0))
        for cat in all_cats:
            summary.append(total_counts[cat])
        writer.writerow(summary)

        if has_access and total_requests > 0:
            def _pct(v):
                if v == 0:
                    return "0%"
                p = v / total_requests * 100
                # 유효숫자가 나올 때까지 소수점 확장
                digits = 4
                while digits < 10 and round(p, digits) == 0:
                    digits += 1
                return f"{p:.{digits}f}%"

            stats = ["[비율(%)]"]
            stats += ["100%", _pct(total_success)]
            for col in http_err_cols:
                stats.append(_pct(total_http_errors.get(col, 0)))
            stats.append(_pct(grand))
            if http_err_cols:
                stats.append(_pct(max(total_http500 - grand, 0)))
            for cat in all_cats:
                stats.append(_pct(total_counts[cat]))
            writer.writerow(stats)

    print(f"\n결과 파일 저장 완료: {output_path}")


def analyze_server(server_dir: str) -> list[dict]:
    """서버 폴더 하나를 분석하고, 해당 폴더 안에 CSV를 생성한다."""
    server_name = os.path.basename(server_dir)
    log_files = sorted(glob.glob(os.path.join(server_dir, DEFAULT_LOG_PATTERN)))
    if not log_files:
        print(f"  서버 {server_name}: 로그 파일 없음")
        return []

    print(f"  {len(log_files)}개 로그 파일 발견")

    access_map = build_access_map(server_dir)
    if access_map:
        print(f"  access 로그 {len(access_map)}일치 분석 완료")

    total_counts: Counter[str] = Counter()
    total_success = 0
    total_http_errors: Counter[str] = Counter()
    per_file_data: list[dict] = []
    assigned_dates: set[str] = set()

    fargrs_ora_keys: set[str] = set()

    for log_file in log_files:
        fname = os.path.basename(log_file)
        date_str = extract_date(fname)
        result = analyze_sd_log(log_file, fargrs_ora_keys=fargrs_ora_keys)
        fargrs_ora_keys = result["fargrs_ora_keys"]

        total_counts.update(result["error_counts"])

        success = 0
        http_errors: Counter[str] = Counter()
        if date_str not in assigned_dates:
            access_data = access_map.get(date_str, {})
            success = access_data.get("success", 0)
            http_errors = access_data.get("http_errors", Counter())
            assigned_dates.add(date_str)
            total_success += success
            total_http_errors.update(http_errors)

        file_data = {
            "file": fname,
            "date": date_str,
            "server": server_name,
            "error_counts": result["error_counts"],
            "success_count": success,
            "http_errors": http_errors,
        }
        per_file_data.append(file_data)

        total = sum(result["error_counts"].values())
        top3 = result["error_counts"].most_common(3)
        top_str = ", ".join(f"{c}={n}" for c, n in top3)
        print(f"    {fname}: ERROR {total}건 ({top_str})")

    # 날짜별 합산
    date_groups: dict[str, list[dict]] = defaultdict(list)
    for d in per_file_data:
        date_groups[d["date"]].append(d)

    per_date_data: list[dict] = []
    for date_str in sorted(date_groups.keys()):
        items = date_groups[date_str]
        merged_counts: Counter[str] = Counter()
        merged_success = 0
        merged_http: Counter[str] = Counter()
        for d in items:
            merged_counts.update(d["error_counts"])
            merged_success += d.get("success_count", 0)
            if d.get("http_errors"):
                merged_http.update(d["http_errors"])
        per_date_data.append({
            "file": date_str,
            "date": date_str,
            "server": server_name,
            "error_counts": merged_counts,
            "success_count": merged_success,
            "http_errors": merged_http,
        })

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        server_dir, f"sd_error_report_server{server_name}_{timestamp}.csv",
    )
    write_sd_result(
        per_date_data, total_counts, output_path, row_label="날짜",
        total_success=total_success, total_http_errors=total_http_errors,
    )

    grand = sum(total_counts.values())
    print(f"  서버 {server_name} 합계: 성공 {total_success:,}건 / ERROR {grand}건")

    return per_date_data


def write_date_summary(all_data: list[dict], output_path: str) -> None:
    """날짜별로 모든 서버의 데이터를 통합한 CSV를 생성한다."""
    date_groups: dict[str, list[dict]] = defaultdict(list)
    for d in all_data:
        date_groups[d["date"]].append(d)

    date_rows: list[dict] = []
    total_counts: Counter[str] = Counter()
    total_http_errors: Counter[str] = Counter()
    total_success = 0

    for date_str in sorted(date_groups.keys()):
        items = date_groups[date_str]
        counts: Counter[str] = Counter()
        day_http: Counter[str] = Counter()
        day_success = sum(d.get("success_count", 0) for d in items)
        for d in items:
            counts.update(d["error_counts"])
            if d.get("http_errors"):
                day_http.update(d["http_errors"])

        date_rows.append({
            "file": date_str,
            "error_counts": counts,
            "success_count": day_success,
            "http_errors": day_http,
        })
        total_counts.update(counts)
        total_http_errors.update(day_http)
        total_success += day_success

    write_sd_result(
        date_rows, total_counts, output_path,
        row_label="날짜", total_success=total_success,
        total_http_errors=total_http_errors,
    )


def main() -> None:
    server_dirs = sorted(
        d for d in glob.glob(os.path.join(DEFAULT_LOG_DIR, "*"))
        if os.path.isdir(d)
    )
    if not server_dirs:
        print(f"서버 폴더를 찾을 수 없습니다: {DEFAULT_LOG_DIR}/*/")
        return

    print(f"총 {len(server_dirs)}개 서버 폴더를 분석합니다.")

    all_data: list[dict] = []
    for server_dir in server_dirs:
        server_name = os.path.basename(server_dir)
        print(f"\n{'=' * 60}")
        print(f"  서버 {server_name} 분석 시작")
        print(f"{'=' * 60}")
        data = analyze_server(server_dir)
        all_data.extend(data)

    if not all_data:
        print("\n분석할 로그 파일이 없습니다.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    date_output = os.path.join(DEFAULT_LOG_DIR, f"sd_error_report_by_date_{timestamp}.csv")
    write_date_summary(all_data, date_output)

    grand = sum(sum(d["error_counts"].values()) for d in all_data)
    total_success = sum(d.get("success_count", 0) for d in all_data)
    total_http: Counter[str] = Counter()
    for d in all_data:
        if d.get("http_errors"):
            total_http.update(d["http_errors"])

    print(f"\n{'=' * 60}")
    print(f"  전체 통합 결과")
    print(f"{'=' * 60}")
    print(f"  서버 수: {len(server_dirs)}")
    if total_success:
        print(f"  성공(HTTP 200/201) 합계: {total_success:,}건")
    if total_http:
        print(f"\n  [Access 로그 - HTTP 응답별 건수]")
        for code, cnt in sorted(total_http.items()):
            print(f"    {code}: {cnt:,}건")
    print(f"\n  서버 ERROR 합계: {grand:,}건")

    total: Counter[str] = Counter()
    for d in all_data:
        total.update(d["error_counts"])
    print(f"\n  {'카테고리':<45s} {'건수':>6s}")
    print(f"  {'-' * 55}")
    for cat, cnt in sorted(total.items(), key=lambda x: _category_sort_key(x[0])):
        print(f"  {cat:<45s} {cnt:>6d}")
    print(f"  {'-' * 55}")
    print(f"  {'합계':<45s} {grand:>6d}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
