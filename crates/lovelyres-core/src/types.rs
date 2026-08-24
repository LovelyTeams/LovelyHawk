//! Cross-domain value types shared without UI/runtime coupling.

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

pub use crate::domain::{CommandOutput, CommandRunner, ServiceAction, ServiceActionResult};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pagination {
    pub page: usize,
    pub page_size: usize,
}

impl Pagination {
    pub const MAX_PAGE_SIZE: usize = 10_000;

    pub fn new(page: usize, page_size: usize) -> CoreResult<Self> {
        if page == 0 || !(1..=Self::MAX_PAGE_SIZE).contains(&page_size) {
            return Err(CoreError::validation(
                "pagination",
                format!(
                    "page must be non-zero and page_size must be 1..={}",
                    Self::MAX_PAGE_SIZE
                ),
            ));
        }
        Ok(Self { page, page_size })
    }

    pub fn offset(self) -> usize {
        self.page.saturating_sub(1).saturating_mul(self.page_size)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: usize,
    pub page_size: usize,
    pub total: usize,
    pub has_more: bool,
}

impl<T> Page<T> {
    pub fn from_items(items: Vec<T>, pagination: Pagination, total: usize) -> Self {
        let consumed = pagination.offset().saturating_add(items.len());
        Self {
            items,
            page: pagination.page,
            page_size: pagination.page_size,
            total,
            has_more: consumed < total,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: Vec<String>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BashEnvironmentInfo {
    pub shell: String,
    pub version: String,
    pub supports_completion: bool,
    pub supports_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandCompletion {
    pub candidates: Vec<String>,
    pub replacement_start: usize,
    pub replacement_end: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_is_bounded_and_overflow_safe() {
        assert!(Pagination::new(0, 10).is_err());
        assert!(Pagination::new(1, Pagination::MAX_PAGE_SIZE + 1).is_err());
        let pagination = Pagination::new(usize::MAX, 10_000).unwrap();
        assert_eq!(pagination.offset(), usize::MAX);
        let page = Page::from_items(vec![1, 2], pagination, usize::MAX);
        assert!(!page.has_more);
    }
}
