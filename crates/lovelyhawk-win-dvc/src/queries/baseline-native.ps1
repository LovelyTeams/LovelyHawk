# Read only local SAM parameters and eight fixed system audit subcategories.
# No privilege adjustment, remote server, policy setter or secret is requested.
$ProgressPreference = 'SilentlyContinue'
$baselineNative = @{}
try {
  if (-not ('LovelyHawkBaselineV3' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class LovelyHawkBaselineV3 {
  [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
  private static extern uint NetUserModalsGet(string server, uint level, out IntPtr buffer);
  [DllImport("netapi32.dll")]
  private static extern uint NetApiBufferFree(IntPtr buffer);
  [DllImport("advapi32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.U1)]
  private static extern bool AuditQuerySystemPolicy(ref Guid category, uint count, out IntPtr buffer);
  [DllImport("advapi32.dll")]
  private static extern void AuditFree(IntPtr buffer);
  [StructLayout(LayoutKind.Sequential)]
  private struct PasswordPolicy {
    public uint MinimumLength, MaximumAge, MinimumAge, ForceLogoff, HistoryLength;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct LockoutPolicy {
    public uint Duration, ObservationWindow, Threshold;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct AuditPolicy {
    public Guid Subcategory;
    public uint Flags;
    public Guid Category;
  }
  private static string Failure(uint code) {
    return code == 5 || code == 1314 ? "permission-denied" : "query-failed";
  }
  public static Dictionary<string, object> Read() {
    var result = new Dictionary<string, object>();
    IntPtr buffer = IntPtr.Zero;
    try {
      uint code = NetUserModalsGet(null, 0, out buffer);
      if (code == 0 && buffer != IntPtr.Zero) {
        var policy = (PasswordPolicy)Marshal.PtrToStructure(buffer, typeof(PasswordPolicy));
        result["passwordLength"] = policy.MinimumLength;
        result["passwordHistory"] = policy.HistoryLength;
        result["passwordMinAgeSeconds"] = policy.MinimumAge;
      } else result["passwordPolicyError"] = Failure(code);
    } finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
    buffer = IntPtr.Zero;
    try {
      uint code = NetUserModalsGet(null, 3, out buffer);
      if (code == 0 && buffer != IntPtr.Zero) {
        var policy = (LockoutPolicy)Marshal.PtrToStructure(buffer, typeof(LockoutPolicy));
        result["lockoutThreshold"] = policy.Threshold;
        result["lockoutDurationSeconds"] = policy.Duration;
        result["lockoutResetSeconds"] = policy.ObservationWindow;
      } else result["lockoutPolicyError"] = Failure(code);
    } finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
    // Query each fixed GUID separately; verify the returned identity before reading flags.
    string[] names = { "auditLogon", "auditLockout", "auditSpecialLogon", "auditProcessCreation",
      "auditPolicyChange", "auditUserAccount", "auditSecurityGroup", "auditCredentialValidation" };
    string[] suffixes = { "9215", "9217", "921b", "922b", "922f", "9235", "9237", "923f" };
    for (int index = 0; index < names.Length; index++) {
      var guid = new Guid("0cce" + suffixes[index] + "-69ae-11d9-bed3-505054503030");
      buffer = IntPtr.Zero;
      try {
        if (AuditQuerySystemPolicy(ref guid, 1, out buffer)) {
          if (buffer == IntPtr.Zero) { result[names[index] + "Error"] = "query-failed"; continue; }
          var policy = (AuditPolicy)Marshal.PtrToStructure(buffer, typeof(AuditPolicy));
          if (policy.Subcategory == guid) result[names[index]] = policy.Flags;
          else result[names[index] + "Error"] = "identity-mismatch";
        } else result[names[index] + "Error"] = Failure((uint)Marshal.GetLastWin32Error());
      } finally { if (buffer != IntPtr.Zero) AuditFree(buffer); }
    }
    return result;
  }
}
'@
  }
  $baselineNative = [LovelyHawkBaselineV3]::Read()
} catch { $baselineNative = @{ nativePolicyError = 'unavailable' } }
