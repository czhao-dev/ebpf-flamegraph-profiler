//! Native, self-contained SVG flame graph renderer - no `flamegraph.pl`
//! or external JS dependency. Produces an icicle layout (root at top,
//! deeper frames below), color-coded by [`FrameKind`], with embedded
//! click-to-zoom and search.

use std::io::Write;

use crate::folded::Aggregator;
use crate::symbolize::{Frame, FrameKind};

const ROW_HEIGHT: f64 = 18.0;
const WIDTH: f64 = 1200.0;

pub struct FlameNode {
    pub name: String,
    pub kind: FrameKind,
    pub value: u64,
    pub children: Vec<FlameNode>,
}

impl FlameNode {
    fn root() -> Self {
        FlameNode {
            name: "all".to_string(),
            kind: FrameKind::Unknown,
            value: 0,
            children: Vec::new(),
        }
    }
}

pub fn build_tree(agg: &Aggregator) -> FlameNode {
    let mut root = FlameNode::root();
    for (frames, count) in agg.iter() {
        root.value += count;
        insert(&mut root, frames, *count);
    }
    root
}

fn insert(node: &mut FlameNode, frames: &[Frame], count: u64) {
    let Some((first, rest)) = frames.split_first() else {
        return;
    };
    let label = first.label();
    let kind = first.kind();
    let idx = node
        .children
        .iter()
        .position(|c| c.name == label && c.kind == kind);
    let child = match idx {
        Some(i) => &mut node.children[i],
        None => {
            node.children.push(FlameNode {
                name: label,
                kind,
                value: 0,
                children: Vec::new(),
            });
            node.children.last_mut().unwrap()
        }
    };
    child.value += count;
    insert(child, rest, count);
}

fn max_depth(node: &FlameNode) -> u32 {
    node.children
        .iter()
        .map(|c| 1 + max_depth(c))
        .max()
        .unwrap_or(0)
}

pub fn render(tree: &FlameNode, w: &mut impl Write) -> std::io::Result<()> {
    let depth = max_depth(tree);
    let height = (depth as f64 + 1.0) * ROW_HEIGHT + 24.0;
    let total = tree.value.max(1) as f64;

    writeln!(w, r#"<?xml version="1.0" standalone="no"?>"#)?;
    writeln!(
        w,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height:.0}" viewBox="0 0 {WIDTH} {height:.0}" font-family="monospace" font-size="12">"#
    )?;
    writeln!(
        w,
        r##"<rect x="0" y="0" width="{WIDTH}" height="{height:.0}" fill="#ffffff"/>"##
    )?;

    render_node(tree, w, 0.0, 0, total)?;

    write!(w, "{}", interactive_script())?;
    writeln!(w, "</svg>")?;
    Ok(())
}

/// Click-to-zoom (rescale the clicked frame's subtree to full width) and
/// a `?`-triggered regex search that outlines matching frames in red.
/// Self-contained: no external JS libraries.
fn interactive_script() -> String {
    format!(
        r#"<script><![CDATA[
(function() {{
    var svg = document.currentScript.parentNode;
    var WIDTH = {WIDTH};
    var frames = Array.prototype.slice.call(svg.querySelectorAll('g.frame'));

    function zoomTo(x0, w0) {{
        var scale = w0 > 0 ? WIDTH / w0 : 1;
        frames.forEach(function(g) {{
            var rect = g.querySelector('rect');
            var text = g.querySelector('text');
            var ox = parseFloat(rect.getAttribute('data-x0'));
            var ow = parseFloat(rect.getAttribute('data-w0'));
            var nx = (ox - x0) * scale;
            var nw = ow * scale;
            rect.setAttribute('x', nx);
            rect.setAttribute('width', Math.max(nw, 0));
            if (text) {{
                text.setAttribute('x', nx + 2);
                text.style.display = nw > 30 ? '' : 'none';
            }}
            g.style.display = (nw <= 0 || nx > WIDTH || nx + nw < 0) ? 'none' : '';
        }});
    }}

    frames.forEach(function(g) {{
        g.style.cursor = 'pointer';
        g.addEventListener('click', function() {{
            var rect = g.querySelector('rect');
            zoomTo(parseFloat(rect.getAttribute('data-x0')), parseFloat(rect.getAttribute('data-w0')));
        }});
    }});

    svg.addEventListener('dblclick', function() {{ zoomTo(0, WIDTH); }});

    window.addEventListener('keydown', function(ev) {{
        if (ev.key !== '/') return;
        var pattern = window.prompt('Search (regex):');
        if (!pattern) return;
        var re;
        try {{ re = new RegExp(pattern); }} catch (e) {{ return; }}
        frames.forEach(function(g) {{
            var rect = g.querySelector('rect');
            var match = re.test(g.getAttribute('data-name') || '');
            rect.setAttribute('stroke', match ? '#ff0000' : 'white');
            rect.setAttribute('stroke-width', match ? '2' : '0.5');
        }});
    }});
}})();
]]></script>
"#
    )
}

fn render_node(
    node: &FlameNode,
    w: &mut impl Write,
    x0: f64,
    depth: u32,
    total: f64,
) -> std::io::Result<()> {
    if node.value == 0 {
        return Ok(());
    }
    let width = (node.value as f64 / total) * WIDTH;
    let y = depth as f64 * ROW_HEIGHT;
    let label = escape_xml(&node.name);

    writeln!(w, r#"<g class="frame" data-name="{label}">"#)?;
    writeln!(
        w,
        r#"<rect x="{x0:.3}" y="{y:.3}" width="{width:.3}" height="{ROW_HEIGHT:.0}" fill="{}" data-x0="{x0:.6}" data-w0="{width:.6}"><title>{label} ({} samples)</title></rect>"#,
        color_for(node.kind),
        node.value,
    )?;
    if width > 30.0 {
        writeln!(
            w,
            r#"<text x="{:.3}" y="{:.3}" clip-path="none">{label}</text>"#,
            x0 + 2.0,
            y + ROW_HEIGHT * 0.75
        )?;
    }
    writeln!(w, "</g>")?;

    let mut child_x = x0;
    for child in &node.children {
        render_node(child, w, child_x, depth + 1, total)?;
        child_x += (child.value as f64 / total) * WIDTH;
    }
    Ok(())
}

fn color_for(kind: FrameKind) -> &'static str {
    match kind {
        FrameKind::Kernel => "#e08030",
        FrameKind::User => "#3b82c4",
        FrameKind::Unknown => "#b0b0b0",
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolize::Frame;

    fn sample_agg() -> Aggregator {
        let mut agg = Aggregator::new();
        agg.add(
            vec![Frame::User("main".into()), Frame::User("compute".into())],
            10,
        );
        agg.add(
            vec![Frame::User("main".into()), Frame::Kernel("do_idle".into())],
            5,
        );
        agg
    }

    #[test]
    fn tree_aggregates_shared_prefix() {
        let agg = sample_agg();
        let tree = build_tree(&agg);
        assert_eq!(tree.value, 15);
        assert_eq!(tree.children.len(), 1);
        let main = &tree.children[0];
        assert_eq!(main.name, "main");
        assert_eq!(main.value, 15);
        assert_eq!(main.children.len(), 2);
    }

    #[test]
    fn renders_well_formed_xml_with_expected_names() {
        let agg = sample_agg();
        let tree = build_tree(&agg);
        let mut out = Vec::new();
        render(&tree, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();

        roxmltree::Document::parse(&text).expect("SVG must be well-formed XML");
        assert!(text.contains("compute"));
        assert!(text.contains("do_idle"));
        assert!(text.contains("main"));
    }

    #[test]
    fn escapes_special_characters_in_frame_names() {
        let mut agg = Aggregator::new();
        agg.add(vec![Frame::User("A<B>&\"C\"".into())], 1);
        let tree = build_tree(&agg);
        let mut out = Vec::new();
        render(&tree, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        roxmltree::Document::parse(&text)
            .expect("SVG must be well-formed XML even with special chars in names");
    }
}
