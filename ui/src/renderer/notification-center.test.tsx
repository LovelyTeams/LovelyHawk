import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { NotificationCenter, NotificationContext, TransientNotice } from "./NotificationCenter";
import { initialNotificationState, notificationReducer, publicNotificationText } from "./notification-state";

describe("global notification center", () => {
  it("expires or dismisses only the toast, retains unread history and clears explicitly", () => {
    const shown = notificationReducer(initialNotificationState,{type:"message",source:"Windows",message:"完成",severity:"success",now:100});
    const expired = notificationReducer(shown,{type:"expire",now:4000});
    expect(expired.notifications).toHaveLength(0); expect(expired.history).toHaveLength(1); expect(expired.history[0]?.read).toBe(false);
    const read = notificationReducer(expired,{type:"read"}); expect(read.history[0]?.read).toBe(true);
    expect(notificationReducer(shown,{type:"dismiss",id:shown.notifications[0]!.id}).history).toHaveLength(1);
    expect(notificationReducer(read,{type:"clear"})).toMatchObject({history:[],notifications:[],omitted:0});
  });
  it("removes inline transient banners under the global provider and preserves contextual validation", () => {
    const view=(inline=false)=><NotificationContext.Provider value={()=>undefined}><TransientNotice source="测试" message="完成" inline={inline}><div>旧横条</div></TransientNotice></NotificationContext.Provider>;
    expect(renderToStaticMarkup(view())).not.toContain("旧横条");
    expect(renderToStaticMarkup(view(true))).toContain("旧横条");
  });
  it("bounds and redacts public notices; hostile markup stays literal", () => {
    expect(publicNotificationText("password=secret token=hidden ssh://user:password@host")).not.toMatch(/secret|hidden|user:password/u);
    expect(publicNotificationText("x".repeat(5000))).toContain("内容已截断");
    const state=notificationReducer(initialNotificationState,{type:"message",source:"测试",message:"<script>bad()</script>",severity:"error",now:1});
    const html=renderToStaticMarkup(<NotificationCenter history={state.history} omitted={3} onClose={()=>undefined} onClear={()=>undefined} onRemove={()=>undefined}/>);
    expect(html).toContain("&lt;script&gt;"); expect(html).not.toContain("<script>"); expect(html).toContain("3 条较早通知"); expect(html).toContain('aria-modal="true"');
  });
});
