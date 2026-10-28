/**
 * How long a single-use plan is still good for, written the way a person says
 * it.
 *
 * Every confirmation dialog used to print the raw number of seconds, so nine
 * different places asked an operator to divide three hundred by sixty — in the
 * one screen where they are about to do something destructive and are least
 * inclined to do arithmetic. The number is the same; only the reading changed.
 */
export function planExpiryLabel(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "已失效";
  const whole = Math.floor(seconds);
  if (whole < 60) return `${whole} 秒`;
  const minutes = Math.floor(whole / 60);
  const rest = whole % 60;
  // Hours only exist if someone raises a TTL far past what any plan uses
  // today; saying "90 分钟" would still be readable, but "1 小时 30 分" is how
  // it would be said out loud.
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    const spare = minutes % 60;
    return spare === 0 ? `${hours} 小时` : `${hours} 小时 ${spare} 分`;
  }
  return rest === 0 ? `${minutes} 分钟` : `${minutes} 分 ${rest} 秒`;
}
