// backend/src/routes/notes.js
const express = require('express');
const mongoose = require('mongoose');
const { z } = require('zod');

const router = express.Router();
const Note = require('../models/Note');
const auth = require('../middlewares/auth');

// Zod schemas for create/update
const createNoteSchema = z.object({
  title: z.string().min(1),
  content: z.string().min(1),
});

const updateNoteSchema = z.object({
  title: z.string().min(1),
  content: z.string().min(1),
});

function isValidId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

router.get('/', auth, async (req, res, next) => {
  try {
    const { q = '', page = 1, limit = 20, sort = 'createdAt:desc' } = req.query;
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const perPage = Math.min(200, parseInt(limit, 10) || 20);
    const skip = (pageNum - 1) * perPage;

    let sortObj = { createdAt: -1 };
    if (sort && typeof sort === 'string') {
      const [field, dir] = sort.split(':');
      if (field && field !== 'relevance') {
        const direction = dir === 'asc' ? 1 : -1;
        sortObj = { [field]: direction };
      }
    }

    const baseQuery = {};
    if (req.userId) baseQuery.user = req.userId;

    if (q && String(q).trim()) {
      const trimmed = String(q).trim();
      const textQuery = { ...baseQuery, $text: { $search: trimmed } };

      if (String(sort).startsWith('relevance')) {
        const docs = await Note.find(textQuery, { score: { $meta: "textScore" } })
          .sort({ score: { $meta: "textScore" }, ...sortObj })
          .skip(skip)
          .limit(perPage)
          .exec();

        const total = await Note.countDocuments(textQuery).exec();
        const totalPages = Math.ceil(total / perPage);
        return res.json({ notes: docs, page: pageNum, perPage, total, totalPages });
      }

      const docs = await Note.find(textQuery, { score: { $meta: "textScore" } })
        .sort({ ...sortObj, score: { $meta: "textScore" } })
        .skip(skip)
        .limit(perPage)
        .exec();

      const total = await Note.countDocuments(textQuery).exec();
      const totalPages = Math.ceil(total / perPage);
      return res.json({ notes: docs, page: pageNum, perPage, total, totalPages });
    } else {
      const docs = await Note.find(baseQuery)
        .sort(sortObj)
        .skip(skip)
        .limit(perPage)
        .exec();

      const total = await Note.countDocuments(baseQuery).exec();
      const totalPages = Math.ceil(total / perPage);
      return res.json({ notes: docs, page: pageNum, perPage, total, totalPages });
    }
  } catch (err) {
    next(err);
  }
});

router.post('/', auth, async (req, res, next) => {
  try {
    const parsed = createNoteSchema.parse(req.body);
    const note = new Note({
      title: parsed.title.trim(),
      content: parsed.content.trim(),
      user: req.userId || undefined,
    });
    const created = await note.save();
    return res.status(201).json(created);
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ message: 'Invalid data', errors: err.errors });
    }
    next(err);
  }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ message: "Invalid note id" });
    const note = await Note.findById(id).exec();
    if (!note) return res.status(404).json({ message: "Note not found" });
    if (note.user && String(note.user) !== String(req.userId)) return res.status(403).json({ message: "Forbidden" });
    return res.json(note);
  } catch (err) {
    next(err);
  }
});

router.put('/:id', auth, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ message: "Invalid note id" });
    const parsed = updateNoteSchema.parse(req.body);

    const note = await Note.findById(id).exec();
    if (!note) return res.status(404).json({ message: "Note not found" });
    if (note.user && String(note.user) !== String(req.userId)) return res.status(403).json({ message: "Forbidden" });

    note.title = parsed.title.trim();
    note.content = parsed.content.trim();
    const updated = await note.save();
    return res.json(updated);
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ message: 'Invalid data', errors: err.errors });
    }
    next(err);
  }
});

router.delete('/:id', auth, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ message: "Invalid note id" });
    const note = await Note.findById(id).exec();
    if (!note) return res.status(404).json({ message: "Note not found" });
    if (note.user && String(note.user) !== String(req.userId)) return res.status(403).json({ message: "Forbidden" });
    await note.deleteOne();
    return res.json({ success: true, id });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
