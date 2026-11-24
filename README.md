# Helios Advance BBS

A modern bulletin board system in the spirit of Virtual BBS and Virtual Advance. Go engine,
Lua scripting layer, Free Pascal tools. AGPL-3.0-only with the Scripting API Exception in
`LICENSE.exception`.

Nothing runs yet. `bash check.sh` is the only definition of green; see `CLAUDE.md`.

Questions about the project, and about how AI is used in it: [docs/faq.md](docs/faq.md).

After four attempts at agentic programming I'm pausing this project for now. Even Anthropic's
most advanced models feel well short of how they're marketed. At their best they reasoned to me
like a capable high school senior or a first year college student. They had all the information
they needed, yet in my experience they consistently took the quickest and easiest path and never
thought through the long term consequences. When they weren't at their best the decision making
felt more like a pre-teen or a teenager, silently dropping work and then trying to cover it up when
called out.

Attempt four started out well. The EARS requirements, contracts and mechanical checks seemed to fix
the cheating that sank attempts one to three. This time the failure was in reasoning. About a week
ago, for no reason I can find, the model's reasoning plummeted. I've always kept myself in the
middle so I can control the shape of the work and be a check on the model. But I've spent the last
week fighting the model just to get it to apply the most basic of reasoning instead of spitting out
an answer in under 30 seconds. Nothing I've tried fixes it. I removed its memory, removed
CLAUDE.md, checked every setting, added new rules and new checks, and even had another model try to
refute the primary one. It's stuck in this mode and nothing gets it out. So every session is me
walking it through one step at a time, even when I tell it to make a plan. In this state the model
is, to me, fundamentally broken and useless. I even had Opus and Fable read the session logs. They
could measure the failures, but neither could find a cause, and nothing they suggested fixed it.

I will pick it back up at some point, but not until I see major improvements in the models.
