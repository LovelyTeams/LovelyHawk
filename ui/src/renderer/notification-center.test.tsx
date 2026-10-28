import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { NotificationCenter, NotificationContext, NotificationOpenContext, TransientNotice } from "./NotificationCenter";
import { NoticeSummary } from "./NoticeSummary";
import { initialNotificationState, notificationReducer, publicNotificationText } from "./notification-state";

describe("global notification center", () => {
  it("does not repeat a collection notice after its toast expires or the module remounts", () => {
    const message = {type:"message",source:"启动项",message:"编码解码器：部分读取",severity:"warning",key:"host-a:collection-1",now:10} as const;
    const shown = notificationReducer(initialNotificationState, message);
    const expired = notificationReducer(shown,{type:"expire",now:5000});
    expect(notificationReducer(expired,{...message,now:6000})).toBe(expired);
    const refreshed = notificationReducer(expired,{...message,key:"host-a:collection-2",now:7000});
    expect(refreshed.history).toHaveLength(2);
    const otherHost = notificationReducer(refreshed,{...message,key:"host-b:collection-1",message:"另一主机：部分读取",now:8000});
    expect(otherHost.history).toHaveLength(3);
    const cleared = notificationReducer(otherHost,{type:"clear"});
    expect(notificationReducer(cleared,{...message,now:9000}).history).toHaveLength(1);
  });
  it("keeps large warning text out of the page and offers an accessible notification entry", () => {
    const notice = <NoticeSummary source="启动项" summary="部分读取 · 查看说明" messages={["权限读取缺口".repeat(300)]} />;
    const html = renderToStaticMarkup(<NotificationContext.Provider value={()=>undefined}><NotificationOpenContext.Provider value={()=>undefined}>{notice}</NotificationOpenContext.Provider></NotificationContext.Provider>);
    expect(html).toContain("部分读取 · 查看说明"); expect(html).toContain('aria-haspopup="dialog"');
    expect(html).not.toContain("权限读取缺口"); expect(html).not.toContain("<details");
    const standalone = renderToStaticMarkup(notice);
    expect(standalone).toContain("<details"); expect(standalone).toContain("权限读取缺口"); expect(standalone).not.toContain(" open=");
  });
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
