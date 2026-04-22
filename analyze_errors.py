import re
import sys
import glob
import os
import csv
from datetime import datetime
from collections import Counter
from error_codes import ERROR_CODES

DEFAULT_LOG_DIR = os.path.join(os.path.dirname(__file__), "pg")
DEFAULT_LOG_PATTERN = "pg.log.*.log"
DATE_FROM_FILENAME_RE = re.compile(r"pg\.log\.(\d{4}-\d{2}-\d{2})\.\d+\.log")

FAILURE_MARKER = "Finished Job: [FAILURE]"
ERROR_CODE_RE = re.compile(r"errorCode='([^']+)'")
IGNORE_CODES = {"null"}

GPKI_ERROR_RE = re.compile(
    r"ERROR\s+c\.e\.s\.t\.s\.GpkiLocalAmanoService\s+-\s+(.+)"
)
CAUSED_BY_RE = re.compile(r"^Caused by:\s+(.+)")
LOG_LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
GPKI_SKIP_MSGS = {"Exception[255]"}


def find_log_files(base_dir: str, pattern: str) -> list[str]:
    """base_dir 하위를 재귀 탐색하여 pattern에 맞는 로그 파일 목록을 반환한다."""
    return sorted(glob.glob(os.path.join(base_dir, "**", pattern), recursive=True))


def analyze_log_file(log_path: str) -> dict:
    """로그 파일을 한 번 순회하며 모든 통계를 수집한다."""
    error_codes: list[str] = []
    total_jobs = 0
    failures = 0
    gpki_counts: Counter[str] = Counter()

    # Gpki 스택트레이스 스캔 상태 (마지막 Caused by 추적)
    gpki_pending: str | None = None
    gpki_last_caused: str | None = None

    # FAILURE 스택트레이스 스캔 상태 (첫 번째 Caused by 추적)
    failure_pending_code: str | None = None
    failure_first_caused: str | None = None

    def _commit_gpki():
        nonlocal gpki_pending, gpki_last_caused
        if gpki_pending is not None:
            if gpki_last_caused:
                key = f"{gpki_pending} | Caused by: {gpki_last_caused}"
            else:
                key = gpki_pending
            gpki_counts[key] += 1
            gpki_pending = None
            gpki_last_caused = None

    def _commit_failure():
        nonlocal failure_pending_code, failure_first_caused
        if failure_pending_code is not None:
            if failure_first_caused:
                key = f"{failure_pending_code} | Caused by: {failure_first_caused}"
            else:
                key = failure_pending_code
            error_codes.append(key)
            failure_pending_code = None
            failure_first_caused = None

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "Finished Job:" in line:
                _commit_failure()
                _commit_gpki()
                total_jobs += 1
                if "[FAILURE]" in line:
                    failures += 1
                    m = ERROR_CODE_RE.search(line)
                    if m and m.group(1) not in IGNORE_CODES:
                        failure_pending_code = m.group(1)
                        failure_first_caused = None
                continue

            gm = GPKI_ERROR_RE.search(line)
            if gm:
                msg = gm.group(1).strip()

                if msg in GPKI_SKIP_MSGS:
                    continue

                _commit_gpki()
                if "verify" in msg.lower():
                    gpki_pending = f"[Verify] {msg}"
                else:
                    gpki_pending = f"[Sign] {msg}"
                gpki_last_caused = None
                continue

            is_caused_by = CAUSED_BY_RE.match(line)
            is_new_log = LOG_LINE_RE.match(line) if not is_caused_by else None

            if gpki_pending is not None:
                if is_caused_by:
                    gpki_last_caused = is_caused_by.group(1).strip()
                elif is_new_log:
                    _commit_gpki()

            if failure_pending_code is not None:
                if is_caused_by and failure_first_caused is None:
                    failure_first_caused = is_caused_by.group(1).strip()
                elif is_new_log:
                    _commit_failure()

    _commit_gpki()
    _commit_failure()

    return {
        "error_codes": error_codes,
        "total_jobs": total_jobs,
        "failures": failures,
        "gpki_counts": gpki_counts,
    }


def print_summary(total_counter: Counter, total_jobs: int, total_failures: int) -> None:
    print()
    print("=" * 90)
    print(f"  전체 작업(Finished Job) 수 : {total_jobs}")
    print(f"  성공(SUCCESS)              : {total_jobs - total_failures}")
    print(f"  실패(FAILURE)              : {total_failures}")
    if total_jobs > 0:
        print(f"  실패율                     : {total_failures / total_jobs * 100:.2f}%")
    print("=" * 90)

    if not total_counter:
        print("\nFAILURE 에러가 발견되지 않았습니다.")
        return

    print(f"\n{'에러코드':<80} {'건수':>6}  {'설명'}")
    print("-" * 120)
    for code, count in total_counter.most_common():
        base_code = code.split(" | ")[0]
        desc = ERROR_CODES.get(base_code, "(알 수 없는 에러코드)")
        print(f"{code:<80} {count:>6}  {desc}")
    print("-" * 120)
    print(f"{'합계':<80} {sum(total_counter.values()):>6}")
    print("=" * 120)


def write_result_file(
    per_file_data: list[dict],
    total_counter: Counter,
    total_gpki: Counter,
    total_jobs: int,
    total_failures: int,
    output_path: str,
    row_label: str = "파일명",
) -> None:
    """파일별(또는 날짜별) 에러코드 카운트 및 전체 요약을 CSV 결과 파일로 저장한다."""
    all_codes = sorted(total_counter.keys())
    gpki_msgs = [msg for msg, _ in total_gpki.most_common()]

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        header = (
            [row_label, "전체작업", "성공", "전체 실패", "변환 실패", "TSA 실패",
             "전체 실패율(%)", "변환 실패율(%)", "TSA 실패율(%)"]
            + [f"{c} ({ERROR_CODES.get(c.split(' | ')[0], '?')})" for c in all_codes]
            + ["실패합계"]
            + [f"[TSA] {msg}" for msg in gpki_msgs]
        )
        writer.writerow(header)

        for d in per_file_data:
            gpki_file_total = sum(d["gpki_counts"].get(msg, 0) for msg in gpki_msgs)
            conv_failures = max(d["failures"] - gpki_file_total, 0)
            jobs = d["total_jobs"]
            row = [
                d["file"],
                jobs,
                jobs - d["failures"],
                d["failures"],
                conv_failures,
                gpki_file_total,
                f"{d['failures'] / jobs * 100:.3f}" if jobs > 0 else "0.000",
                f"{conv_failures / jobs * 100:.3f}" if jobs > 0 else "0.000",
                f"{gpki_file_total / jobs * 100:.3f}" if jobs > 0 else "0.000",
            ]
            file_total = 0
            for c in all_codes:
                cnt = d["counter"].get(c, 0)
                row.append(cnt)
                file_total += cnt
            row.append(file_total)
            for msg in gpki_msgs:
                cnt = d["gpki_counts"].get(msg, 0)
                row.append(cnt)
            writer.writerow(row)

        writer.writerow([])
        gpki_grand_total = sum(total_gpki[msg] for msg in gpki_msgs)
        conv_failures_total = max(total_failures - gpki_grand_total, 0)
        summary_row = [
            "[합계]",
            total_jobs,
            total_jobs - total_failures,
            total_failures,
            conv_failures_total,
            gpki_grand_total,
            f"{total_failures / total_jobs * 100:.3f}" if total_jobs > 0 else "0.000",
            f"{conv_failures_total / total_jobs * 100:.3f}" if total_jobs > 0 else "0.000",
            f"{gpki_grand_total / total_jobs * 100:.3f}" if total_jobs > 0 else "0.000",
        ]
        for c in all_codes:
            summary_row.append(total_counter[c])
        summary_row.append(sum(total_counter.values()))
        for msg in gpki_msgs:
            summary_row.append(total_gpki[msg])
        writer.writerow(summary_row)

    print(f"\n결과 파일 저장 완료: {output_path}")


def extract_date(filename: str) -> str:
    """파일명에서 날짜(YYYY-MM-DD)를 추출한다."""
    m = DATE_FROM_FILENAME_RE.search(filename)
    return m.group(1) if m else "unknown"


def analyze_server(server_dir: str) -> list[dict]:
    """서버 폴더 하나를 분석하고, 해당 폴더 안에 CSV를 생성한다.
    날짜별 통합용 per-file 데이터 리스트를 반환한다."""
    server_name = os.path.basename(server_dir)
    log_files = sorted(glob.glob(os.path.join(server_dir, DEFAULT_LOG_PATTERN)))
    if not log_files:
        print(f"  서버 {server_name}: 로그 파일 없음")
        return []

    print(f"  {len(log_files)}개 로그 파일 발견")

    error_counter: Counter[str] = Counter()
    grand_total_jobs = 0
    grand_total_failures = 0
    grand_gpki: Counter[str] = Counter()
    per_file_data: list[dict] = []

    for log_file in log_files:
        fname = os.path.basename(log_file)
        result = analyze_log_file(log_file)
        total_jobs = result["total_jobs"]
        total_failures = result["failures"]
        file_counter = Counter(result["error_codes"])

        grand_total_jobs += total_jobs
        grand_total_failures += total_failures
        error_counter.update(file_counter)
        grand_gpki.update(result["gpki_counts"])

        file_data = {
            "file": fname,
            "date": extract_date(fname),
            "server": server_name,
            "total_jobs": total_jobs,
            "failures": total_failures,
            "counter": file_counter,
            "gpki_counts": result["gpki_counts"],
        }
        per_file_data.append(file_data)

        gpki_total = sum(result["gpki_counts"].values())
        print(f"    {fname}: 작업 {total_jobs}, 실패 {total_failures}, Gpki {gpki_total}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(server_dir, f"error_report_server{server_name}_{timestamp}.csv")
    write_result_file(
        per_file_data, error_counter, grand_gpki,
        grand_total_jobs, grand_total_failures, output_path,
    )
    print(f"  서버 {server_name} 합계: 작업 {grand_total_jobs}, "
          f"실패 {grand_total_failures}, Gpki {sum(grand_gpki.values())}")

    return per_file_data


def write_date_summary(all_data: list[dict], output_path: str) -> None:
    """날짜별로 모든 서버의 데이터를 통합한 CSV를 생성한다."""
    from collections import defaultdict
    date_groups: dict[str, list[dict]] = defaultdict(list)
    for d in all_data:
        date_groups[d["date"]].append(d)

    date_rows: list[dict] = []
    total_counter: Counter[str] = Counter()
    total_gpki: Counter[str] = Counter()
    grand_jobs = 0
    grand_failures = 0

    for date_str in sorted(date_groups.keys()):
        items = date_groups[date_str]
        jobs = sum(d["total_jobs"] for d in items)
        fails = sum(d["failures"] for d in items)
        counter: Counter[str] = Counter()
        gpki: Counter[str] = Counter()
        for d in items:
            counter.update(d["counter"])
            gpki.update(d["gpki_counts"])

        date_rows.append({
            "file": date_str,
            "total_jobs": jobs,
            "failures": fails,
            "counter": counter,
            "gpki_counts": gpki,
        })
        grand_jobs += jobs
        grand_failures += fails
        total_counter.update(counter)
        total_gpki.update(gpki)

    write_result_file(
        date_rows, total_counter, total_gpki,
        grand_jobs, grand_failures, output_path,
        row_label="날짜",
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
    date_output = os.path.join(DEFAULT_LOG_DIR, f"error_report_by_date_{timestamp}.csv")
    write_date_summary(all_data, date_output)

    total_jobs = sum(d["total_jobs"] for d in all_data)
    total_failures = sum(d["failures"] for d in all_data)
    total_gpki = sum(sum(d["gpki_counts"].values()) for d in all_data)
    print(f"\n{'=' * 60}")
    print(f"  전체 통합 결과")
    print(f"{'=' * 60}")
    print(f"  서버 수: {len(server_dirs)}")
    print(f"  전체 작업: {total_jobs}, 실패: {total_failures}, Gpki: {total_gpki}")
    if total_jobs > 0:
        print(f"  실패율: {total_failures / total_jobs * 100:.2f}%")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
