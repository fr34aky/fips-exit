//! A QR code as SVG, drawn here: no image, no script, nothing fetched from
//! anywhere. An invoice is long, and a person pays it with another device
//! by pointing that at the screen.

use qrcode::{Color, EcLevel, QrCode};

/// The empty margin a reader needs around a code, in modules.
const MARGIN: usize = 4;

/// `text` as a QR code: an `<svg>` element, black on white whatever the
/// page's colours are. None for text that does not fit in one.
pub fn svg(text: &str) -> Option<String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L).ok()?;
    let (width, modules) = (code.width(), code.to_colors());
    let size = width + 2 * MARGIN;
    // One rectangle for each run of dark modules in a row.
    let mut path = String::new();
    for (y, row) in modules.chunks(width).enumerate() {
        let mut x = 0;
        while x < width {
            let from = x;
            while x < width && row[x] == Color::Dark {
                x += 1;
            }
            if x > from {
                path.push_str(&format!("M{} {}h{}v1h-{}z", from + MARGIN, y + MARGIN, x - from, x - from));
            } else {
                x += 1;
            }
        }
    }
    Some(format!(
        "<svg class=\"qr\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
         shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"The invoice as a QR code\">\
         <rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/><path fill=\"#000\" d=\"{path}\"/></svg>"
    ))
}

/// An invoice as wallets read it from a code: in capitals, which a code
/// holds in less room, after `LIGHTNING:`.
pub fn of_invoice(request: &str) -> Option<String> {
    svg(&format!("LIGHTNING:{}", request.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dark modules a code's SVG draws, as a grid with its margin.
    fn drawn(svg: &str) -> Vec<Vec<bool>> {
        let size: usize = svg.split("viewBox=\"0 0 ").nth(1).unwrap().split(' ').next().unwrap().parse().unwrap();
        let mut grid = vec![vec![false; size]; size];
        let path = svg.split(" d=\"").nth(1).unwrap().split('"').next().unwrap();
        for run in path.split('z').filter(|run| !run.is_empty()) {
            let numbers: Vec<usize> = run
                .split(|c: char| !c.is_ascii_digit())
                .filter(|n| !n.is_empty())
                .map(|n| n.parse().unwrap())
                .collect();
            // M x y h w v 1 h -w
            let (x, y, w) = (numbers[0], numbers[1], numbers[2]);
            assert_eq!((numbers[3], numbers[4]), (1, w), "{run}");
            for cell in &mut grid[y][x..x + w] {
                assert!(!*cell, "drawn twice");
                *cell = true;
            }
        }
        grid
    }

    #[test]
    fn a_code_is_drawn_as_it_is() {
        let text = "LIGHTNING:LNBC640N1P0EXAMPLE";
        let svg = svg(text).unwrap();
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L).unwrap();
        let (width, modules) = (code.width(), code.to_colors());
        let grid = drawn(&svg);
        assert_eq!(grid.len(), width + 2 * MARGIN);
        for (y, row) in grid.iter().enumerate() {
            for (x, dark) in row.iter().enumerate() {
                let inside = (MARGIN..MARGIN + width).contains(&x) && (MARGIN..MARGIN + width).contains(&y);
                let is = inside && modules[(y - MARGIN) * width + (x - MARGIN)] == Color::Dark;
                assert_eq!(*dark, is, "module {x},{y}");
            }
        }
        // The three corners a reader finds a code by.
        for (x, y) in [(0, 0), (width - 7, 0), (0, width - 7)] {
            assert!((0..7).all(|i| grid[y + MARGIN][x + MARGIN + i] && grid[y + MARGIN + 6][x + MARGIN + i]));
        }
        // Nothing in it but what was written here: no script, no link.
        assert!(svg.starts_with("<svg class=\"qr\"") && svg.ends_with("</svg>"));
        assert!(!svg.contains("href") && !svg.contains("script") && !svg.contains("style"));
    }

    #[test]
    fn an_invoice_fits_and_is_written_in_capitals() {
        // As long as invoices get, and longer.
        let request = format!("lnbc640n1p{}", "qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(20));
        let lower = svg(&format!("lightning:{request}")).unwrap();
        let upper = of_invoice(&request).unwrap();
        assert!(drawn(&upper).len() < drawn(&lower).len(), "capitals take a smaller code");
        assert!(svg(&"x".repeat(8000)).is_none(), "what does not fit is no code");
    }
}
