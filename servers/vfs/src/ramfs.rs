//! In-memory filesystem core (v0 mount, design doc §3.1). Pure logic, no
//! interface concerns: node arena, component walk, POSIX-ish open/close
//! refcounting for pending deletes, and stable readdir cookies.

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use ipc::status;

use crate::proto::{vstatus, Stat, Status, KIND_DIR, KIND_FILE};

pub type NodeId = u32;

/// Hard cap on file size (no allocator pressure in v0; ETOOBIG beyond).
pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;

pub const MODE_DIR_DEFAULT: u32 = 0o755;
pub const MODE_FILE_DEFAULT: u32 = 0o644;

enum NodeData {
    File(Vec<u8>),
    Dir(BTreeMap<String, NodeId>),
}

struct Node {
    data: NodeData,
    mode: u32,
    mtime_ns: u64,
    parent: NodeId,
    refs: u32,
    deleted: bool,
}

pub struct RamFs {
    nodes: Vec<Option<Node>>,
    root: NodeId,
}

impl RamFs {
    pub fn new() -> Self {
        let mut fs = Self {
            nodes: Vec::new(),
            root: 0,
        };
        fs.root = fs.alloc_node(NodeData::Dir(BTreeMap::new()), MODE_DIR_DEFAULT, 0, 0);
        fs
    }

    pub fn root(&self) -> NodeId {
        self.root
    }

    fn alloc_node(&mut self, data: NodeData, mode: u32, now_ns: u64, parent: NodeId) -> NodeId {
        self.nodes.push(Some(Node {
            data,
            mode,
            mtime_ns: now_ns,
            parent,
            refs: 0,
            deleted: false,
        }));
        self.nodes.len() as NodeId
    }

    /// Id-based access. A pending-deleted node (unlinked but still open) stays
    /// valid here — POSIX semantics; name lookups go through `walk`, which
    /// cannot reach deleted nodes because unlink removes the directory entry.
    fn get(&self, id: NodeId) -> Result<&Node, Status> {
        if id == 0 {
            return Err(status::EBADCAP);
        }
        match self.nodes.get((id - 1) as usize) {
            Some(Some(n)) => Ok(n),
            _ => Err(vstatus::ENOENT),
        }
    }

    fn get_mut(&mut self, id: NodeId) -> Result<&mut Node, Status> {
        if id == 0 {
            return Err(status::EBADCAP);
        }
        match self.nodes.get_mut((id - 1) as usize) {
            Some(Some(n)) => Ok(n),
            _ => Err(vstatus::ENOENT),
        }
    }

    fn free_slot(&mut self, id: NodeId) {
        if let Some(slot) = self.nodes.get_mut((id - 1) as usize) {
            *slot = None;
        }
    }

    pub fn stat(&self, id: NodeId) -> Result<Stat, Status> {
        let n = self.get(id)?;
        let (kind, size) = match &n.data {
            NodeData::File(data) => (KIND_FILE, data.len() as u64),
            NodeData::Dir(entries) => (KIND_DIR, entries.len() as u64),
        };
        Ok(Stat {
            kind,
            mode: n.mode,
            size,
            mtime_ns: n.mtime_ns,
        })
    }

    fn dir_entries(&self, id: NodeId) -> Result<&BTreeMap<String, NodeId>, Status> {
        match &self.get(id)?.data {
            NodeData::Dir(entries) => Ok(entries),
            NodeData::File(_) => Err(vstatus::ENOTDIR),
        }
    }

    fn file_data(&self, id: NodeId) -> Result<&Vec<u8>, Status> {
        match &self.get(id)?.data {
            NodeData::File(data) => Ok(data),
            NodeData::Dir(_) => Err(vstatus::EISDIR),
        }
    }

    /// Single-component walk; `"."` is self, `".."` is the parent (root is its
    /// own parent — the connection's effective root clamps here in v0).
    pub fn walk(&self, dir: NodeId, component: &str) -> Result<NodeId, Status> {
        match component {
            "." => return self.get(dir).map(|_| dir),
            ".." => {
                let n = self.get(dir)?;
                if n.parent == 0 {
                    return Ok(self.root);
                }
                return Ok(n.parent);
            }
            "" => return Err(vstatus::EINVAL),
            _ => {}
        }
        let entries = self.dir_entries(dir)?;
        entries.get(component).copied().ok_or(vstatus::ENOENT)
    }

    /// Opens a node (increments the pending-delete refcount).
    pub fn node_open(&mut self, id: NodeId) -> Result<(), Status> {
        self.get_mut(id).map(|n| n.refs += 1)
    }

    /// Closes a node; a deleted node is freed on its last close.
    pub fn node_close(&mut self, id: NodeId) {
        let free = match self.nodes.get_mut((id.saturating_sub(1)) as usize) {
            Some(Some(n)) if n.refs > 0 => {
                n.refs -= 1;
                n.deleted && n.refs == 0
            }
            _ => false,
        };
        if free {
            self.free_slot(id);
        }
    }

    pub fn create_file(
        &mut self,
        dir: NodeId,
        name: &str,
        mode: u32,
        now_ns: u64,
    ) -> Result<NodeId, Status> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(vstatus::EINVAL);
        }
        if self.dir_entries(dir)?.contains_key(name) {
            return Err(vstatus::EEXIST);
        }
        let id = self.alloc_node(NodeData::File(Vec::new()), mode, now_ns, dir);
        if let Ok(NodeData::Dir(entries)) = self.get_mut(dir).map(|n| &mut n.data) {
            entries.insert(String::from(name), id);
        }
        self.get_mut(dir)?.mtime_ns = now_ns;
        Ok(id)
    }

    pub fn mkdir(
        &mut self,
        dir: NodeId,
        name: &str,
        mode: u32,
        now_ns: u64,
    ) -> Result<NodeId, Status> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(vstatus::EINVAL);
        }
        if self.dir_entries(dir)?.contains_key(name) {
            return Err(vstatus::EEXIST);
        }
        let id = self.alloc_node(NodeData::Dir(BTreeMap::new()), mode, now_ns, dir);
        if let Ok(NodeData::Dir(entries)) = self.get_mut(dir).map(|n| &mut n.data) {
            entries.insert(String::from(name), id);
        }
        self.get_mut(dir)?.mtime_ns = now_ns;
        Ok(id)
    }

    /// Unlinks a file. Directories are EISDIR (rmdir is not in v0).
    /// If the node is open, it is marked deleted and freed on last close.
    pub fn unlink(&mut self, dir: NodeId, name: &str) -> Result<(), Status> {
        if name.is_empty() || name == "." || name == ".." {
            return Err(vstatus::EINVAL);
        }
        let id = {
            let entries = self.dir_entries(dir)?;
            *entries.get(name).ok_or(vstatus::ENOENT)?
        };
        match &self.get(id)?.data {
            NodeData::Dir(_) => return Err(vstatus::EISDIR),
            NodeData::File(_) => {}
        }
        let refs = self.get(id)?.refs;
        if let Ok(NodeData::Dir(entries)) = self.get_mut(dir).map(|n| &mut n.data) {
            entries.remove(name);
        }
        if refs == 0 {
            self.free_slot(id);
        } else {
            self.get_mut(id)?.deleted = true;
        }
        Ok(())
    }

    /// Renames within the tree. v0 rules: source must exist; destination may
    /// be absent (rename) or an existing *file* (replace); directories are
    /// never replaced; a directory cannot move into its own subtree.
    pub fn rename(
        &mut self,
        src_dir: NodeId,
        src_name: &str,
        dst_dir: NodeId,
        dst_name: &str,
        now_ns: u64,
    ) -> Result<(), Status> {
        if [src_name, dst_name]
            .iter()
            .any(|n| n.is_empty() || *n == "." || *n == ".." || n.contains('/'))
        {
            return Err(vstatus::EINVAL);
        }
        let src = {
            let entries = self.dir_entries(src_dir)?;
            *entries.get(src_name).ok_or(vstatus::ENOENT)?
        };
        let src_is_dir = matches!(self.get(src)?.data, NodeData::Dir(_));

        if dst_dir == src && src_name == dst_name {
            return Err(vstatus::EINVAL);
        }
        if src_is_dir && self.is_ancestor_of(src, dst_dir)? {
            return Err(vstatus::EINVAL);
        }

        let existing = self.dir_entries(dst_dir)?.get(dst_name).copied();
        if let Some(dst) = existing {
            if matches!(self.get(dst)?.data, NodeData::Dir(_)) || src_is_dir {
                let entries = match &self.get(dst)?.data {
                    NodeData::Dir(e) => e,
                    NodeData::File(_) => unreachable!(),
                };
                return Err(if entries.is_empty() {
                    vstatus::EEXIST
                } else {
                    vstatus::ENOTEMPTY
                });
            }
            let refs = self.get(dst)?.refs;
            if refs == 0 {
                self.free_slot(dst);
            } else {
                self.get_mut(dst)?.deleted = true;
            }
        }

        if let Ok(NodeData::Dir(entries)) = self.get_mut(src_dir).map(|n| &mut n.data) {
            entries.remove(src_name);
        }
        if let Ok(NodeData::Dir(entries)) = self.get_mut(dst_dir).map(|n| &mut n.data) {
            entries.insert(String::from(dst_name), src);
        }
        let n = self.get_mut(src)?;
        n.parent = dst_dir;
        n.mtime_ns = now_ns;
        self.get_mut(src_dir)?.mtime_ns = now_ns;
        self.get_mut(dst_dir)?.mtime_ns = now_ns;
        Ok(())
    }

    fn is_ancestor_of(&self, maybe_ancestor: NodeId, mut node: NodeId) -> Result<bool, Status> {
        loop {
            if node == maybe_ancestor {
                return Ok(true);
            }
            let parent = self.get(node)?.parent;
            if parent == 0 || parent == self.root {
                return Ok(parent == maybe_ancestor);
            }
            node = parent;
        }
    }

    /// Reads up to `buf.len()` bytes at `offset`; short read at EOF.
    pub fn read(&self, id: NodeId, offset: u64, buf: &mut [u8]) -> Result<usize, Status> {
        let data = self.file_data(id)?;
        let start = offset.min(data.len() as u64) as usize;
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    /// Writes at `offset`, zero-filling a gap; caps at `MAX_FILE_SIZE`.
    pub fn write(
        &mut self,
        id: NodeId,
        offset: u64,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<usize, Status> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(vstatus::EINVAL)?;
        if end > MAX_FILE_SIZE {
            return Err(status::ETOOBIG);
        }
        let n = match &mut self.get_mut(id)?.data {
            NodeData::File(data) => {
                let end = end as usize;
                if data.len() < end {
                    data.resize(end, 0);
                }
                let start = offset as usize;
                data[start..end].copy_from_slice(bytes);
                bytes.len()
            }
            NodeData::Dir(_) => return Err(vstatus::EISDIR),
        };
        self.get_mut(id)?.mtime_ns = now_ns;
        Ok(n)
    }

    pub fn truncate(&mut self, id: NodeId, size: u64, now_ns: u64) -> Result<(), Status> {
        if size > MAX_FILE_SIZE {
            return Err(status::ETOOBIG);
        }
        match &mut self.get_mut(id)?.data {
            NodeData::File(data) => data.resize(size as usize, 0),
            NodeData::Dir(_) => return Err(vstatus::EISDIR),
        }
        self.get_mut(id)?.mtime_ns = now_ns;
        Ok(())
    }

    /// Directory iteration by cookie: `cookie = 0` starts at the first entry;
    /// the reply's next cookie is `0` at the end. Mutation between calls makes
    /// the cookie advisory (documented in the design doc).
    pub fn readdir(
        &self,
        dir: NodeId,
        cookie: u64,
    ) -> Result<Option<(u64, String, NodeId)>, Status> {
        let entries = self.dir_entries(dir)?;
        let idx = cookie as usize;
        if idx >= entries.len() {
            return Ok(None);
        }
        let (name, id) = entries
            .iter()
            .nth(idx)
            .map(|(n, i)| (n.clone(), *i))
            .expect("in range");
        let next = if idx + 1 >= entries.len() {
            0
        } else {
            (idx + 1) as u64
        };
        Ok(Some((next, name, id)))
    }
}

impl Default for RamFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs() -> RamFs {
        RamFs::new()
    }

    #[test]
    fn walk_dot_dotdot_and_root_clamp() {
        let mut fs = fs();
        let root = fs.root();
        let etc = fs.mkdir(root, "etc", MODE_DIR_DEFAULT, 1).unwrap();
        assert_eq!(fs.walk(root, ".").unwrap(), root);
        assert_eq!(fs.walk(root, "etc").unwrap(), etc);
        assert_eq!(fs.walk(etc, "..").unwrap(), root);
        assert_eq!(fs.walk(root, "..").unwrap(), root, "root clamps at itself");
        assert_eq!(fs.walk(etc, ".").unwrap(), etc);
        assert_eq!(fs.walk(root, "nope"), Err(vstatus::ENOENT));
        assert_eq!(fs.walk(root, ""), Err(vstatus::EINVAL));
    }

    #[test]
    fn create_write_read_stat() {
        let mut fs = fs();
        let root = fs.root();
        let f = fs
            .create_file(root, "hello", MODE_FILE_DEFAULT, 10)
            .unwrap();
        assert_eq!(fs.stat(f).unwrap().kind, KIND_FILE);
        assert_eq!(fs.stat(f).unwrap().size, 0);

        assert_eq!(fs.write(f, 0, b"hello world", 20).unwrap(), 11);
        assert_eq!(fs.stat(f).unwrap().size, 11);
        assert_eq!(fs.stat(f).unwrap().mtime_ns, 20);

        let mut buf = [0u8; 5];
        assert_eq!(fs.read(f, 6, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"world");

        let mut short = [0u8; 32];
        assert_eq!(fs.read(f, 6, &mut short).unwrap(), 5, "short read at EOF");
        assert_eq!(fs.read(f, 100, &mut short).unwrap(), 0);
    }

    #[test]
    fn write_gap_zero_fills_and_caps_size() {
        let mut fs = fs();
        let root = fs.root();
        let f = fs
            .create_file(root, "sparse", MODE_FILE_DEFAULT, 0)
            .unwrap();
        fs.write(f, 4, b"xy", 1).unwrap();
        let mut buf = [7u8; 6];
        assert_eq!(fs.read(f, 0, &mut buf).unwrap(), 6);
        assert_eq!(&buf, b"\0\0\0\0xy");

        assert_eq!(fs.write(f, MAX_FILE_SIZE, b"x", 2), Err(status::ETOOBIG));
    }

    #[test]
    fn truncate_shrinks_and_grows() {
        let mut fs = fs();
        let root = fs.root();
        let f = fs.create_file(root, "t", MODE_FILE_DEFAULT, 0).unwrap();
        fs.write(f, 0, b"0123456789", 1).unwrap();
        fs.truncate(f, 4, 2).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(fs.read(f, 0, &mut buf).unwrap(), 4);
        fs.truncate(f, 6, 3).unwrap();
        assert_eq!(fs.stat(f).unwrap().size, 6);
        let mut buf2 = [9u8; 6];
        fs.read(f, 0, &mut buf2).unwrap();
        assert_eq!(&buf2, b"0123\0\0");
    }

    #[test]
    fn mkdir_duplicate_and_file_name_conflicts() {
        let mut fs = fs();
        let root = fs.root();
        fs.mkdir(root, "a", MODE_DIR_DEFAULT, 0).unwrap();
        assert_eq!(
            fs.mkdir(root, "a", MODE_DIR_DEFAULT, 0),
            Err(vstatus::EEXIST)
        );
        fs.create_file(root, "f", MODE_FILE_DEFAULT, 0).unwrap();
        assert_eq!(
            fs.create_file(root, "f", MODE_FILE_DEFAULT, 0),
            Err(vstatus::EEXIST)
        );
        let f = fs.walk(root, "f").unwrap();
        assert_eq!(fs.dir_entries(f), Err(vstatus::ENOTDIR));
    }

    #[test]
    fn walk_into_file_is_notdir() {
        let mut fs = fs();
        let root = fs.root();
        let f = fs.create_file(root, "f", MODE_FILE_DEFAULT, 0).unwrap();
        assert_eq!(fs.walk(f, "x"), Err(vstatus::ENOTDIR));
        assert_eq!(fs.readdir(f, 0), Err(vstatus::ENOTDIR));
        assert_eq!(fs.read(f, 0, &mut []).unwrap(), 0);
    }

    #[test]
    fn unlink_pending_delete_with_open_handle() {
        let mut fs = fs();
        let root = fs.root();
        let f = fs.create_file(root, "f", MODE_FILE_DEFAULT, 0).unwrap();
        fs.write(f, 0, b"data", 0).unwrap();
        fs.node_open(f).unwrap();

        fs.unlink(root, "f").unwrap();
        assert_eq!(fs.walk(root, "f"), Err(vstatus::ENOENT), "gone from dir");

        // Open handles keep working through the pending delete (POSIX).
        let mut buf = [0u8; 4];
        assert_eq!(fs.read(f, 0, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"data");
        assert_eq!(fs.stat(f).unwrap().size, 4);

        fs.node_close(f);
        assert_eq!(fs.read(f, 0, &mut buf), Err(vstatus::ENOENT), "freed");
    }

    #[test]
    fn unlink_rules() {
        let mut fs = fs();
        let root = fs.root();
        fs.mkdir(root, "d", MODE_DIR_DEFAULT, 0).unwrap();
        assert_eq!(fs.unlink(root, "d"), Err(vstatus::EISDIR));
        assert_eq!(fs.unlink(root, "."), Err(vstatus::EINVAL));
        assert_eq!(fs.unlink(root, "nope"), Err(vstatus::ENOENT));
    }

    #[test]
    fn rename_rules_and_replace() {
        let mut fs = fs();
        let root = fs.root();
        let a = fs.mkdir(root, "a", MODE_DIR_DEFAULT, 0).unwrap();
        let b = fs.mkdir(root, "b", MODE_DIR_DEFAULT, 0).unwrap();
        let f = fs.create_file(root, "f", MODE_FILE_DEFAULT, 0).unwrap();
        fs.write(f, 0, b"new", 0).unwrap();
        let g = fs.create_file(root, "g", MODE_FILE_DEFAULT, 0).unwrap();
        fs.write(g, 0, b"old", 0).unwrap();

        fs.rename(root, "f", a, "f", 1).unwrap();
        assert_eq!(fs.walk(a, "f").unwrap(), f);
        assert_eq!(fs.walk(root, "f"), Err(vstatus::ENOENT));

        fs.rename(a, "f", root, "g", 2).unwrap();
        assert_eq!(fs.walk(root, "g").unwrap(), f, "replaced existing file");
        assert_eq!(fs.stat(g), Err(vstatus::ENOENT), "old node freed");
        let mut buf = [0u8; 3];
        fs.read(f, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"new");

        let empty = fs.mkdir(b, "empty", MODE_DIR_DEFAULT, 0).unwrap();
        assert_eq!(
            fs.rename(root, "g", b, "empty", 3),
            Err(vstatus::EEXIST),
            "directory targets are never replaced"
        );
        assert_eq!(fs.stat(empty).unwrap().kind, KIND_DIR, "target untouched");

        let inner = fs.mkdir(a, "inner", MODE_DIR_DEFAULT, 0).unwrap();
        assert_eq!(
            fs.rename(root, "a", inner, "a", 4),
            Err(vstatus::EINVAL),
            "cannot move a directory into its own subtree"
        );
    }

    #[test]
    fn readdir_cookies_walk_all_entries_and_end() {
        let mut fs = fs();
        let root = fs.root();
        fs.mkdir(root, "aa", MODE_DIR_DEFAULT, 0).unwrap();
        fs.create_file(root, "bb", MODE_FILE_DEFAULT, 0).unwrap();
        fs.create_file(root, "cc", MODE_FILE_DEFAULT, 0).unwrap();

        let mut seen = Vec::new();
        let mut cookie = 0;
        while let Some((next, name, _)) = fs.readdir(root, cookie).unwrap() {
            seen.push(name);
            if next == 0 {
                break;
            }
            cookie = next;
        }
        assert_eq!(seen, vec!["aa", "bb", "cc"], "sorted order");
        assert_eq!(fs.readdir(root, 99).unwrap(), None);
    }
}
