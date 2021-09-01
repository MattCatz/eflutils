/* Get Dwarf Frame state for target crash file.
   Copyright (C) 2021 Matthew Cather
   Copyright (C) 2013, 2014 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "libdwflP.h"
#include "system.h"
#include <fcntl.h>

#ifdef __linux__

#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#endif

struct crash_arg
{
  Elf *crash;
  Elf_Data *note_data;
  size_t thread_note_offset;
  struct __libdwfl_remote_mem_cache *mem_cache;
  Ebl *ebl;
};

struct thread_arg
{
  struct crash_arg *crash_arg;
  size_t note_offset;
};

static pid_t
crash_next_thread (Dwfl *dwfl __attribute__ ((unused)), void *dwfl_arg,
                   void **thread_argp)
{
  struct crash_arg *crash_arg = dwfl_arg;
  Elf *crash = crash_arg->crash;
  GElf_Nhdr nhdr;
  size_t name_offset;
  size_t desc_offset;
  Elf_Data *note_data = crash_arg->note_data;
  size_t offset;

  struct thread_arg *thread_arg;
  if (*thread_argp == NULL)
    {
      crash_arg->thread_note_offset = 0;
      thread_arg = malloc (sizeof (*thread_arg));
      if (thread_arg == NULL)
        {
          __libdwfl_seterrno (DWFL_E_NOMEM);
          return -1;
        }
      thread_arg->crash_arg = crash_arg;
      *thread_argp = thread_arg;
    }
  else
    thread_arg = (struct thread_arg *)*thread_argp;

  while (offset = crash_arg->thread_note_offset,
         offset < note_data->d_size
             && (crash_arg->thread_note_offset = gelf_getnote (
                     note_data, offset, &nhdr, &name_offset, &desc_offset))
                    > 0)
    {
      /* Do not check NAME for now, help broken Linux kernels.  */
      const char *name
          = (nhdr.n_namesz == 0 ? "" : note_data->d_buf + name_offset);
      const char *desc = note_data->d_buf + desc_offset;
      GElf_Word regs_offset;
      size_t nregloc;
      const Ebl_Register_Location *reglocs;
      size_t nitems;
      const Ebl_Core_Item *items;
      if (!ebl_core_note (crash_arg->ebl, &nhdr, name, desc, &regs_offset,
                          &nregloc, &reglocs, &nitems, &items))
        {
          /* This note may be just not recognized, skip it.  */
          continue;
        }
      if (nhdr.n_type != NT_PRSTATUS)
        continue;
      const Ebl_Core_Item *item;
      for (item = items; item < items + nitems; item++)
        if (strcmp (item->name, "pid") == 0)
          break;
      if (item == items + nitems)
        continue;
      uint32_t val32 = read_4ubyte_unaligned_noncvt (desc + item->offset);
      val32 = (elf_getident (crash, NULL)[EI_DATA] == ELFDATA2MSB
                   ? be32toh (val32)
                   : le32toh (val32));
      pid_t tid = (int32_t)val32;
      eu_static_assert (sizeof val32 <= sizeof tid);
      thread_arg->note_offset = offset;
      return tid;
    }

  free (thread_arg);
  return 0;
}

/* Note that the result word size depends on the architecture word size.
   That is sizeof long. */
static bool
crash_memory_read (Dwfl *dwfl, Dwarf_Addr addr, Dwarf_Word *result, void *arg)
{
  // struct __libdwfl_pid_arg *pid_arg = arg;
  Dwfl_Process *process = dwfl->process;
  struct crash_arg *crash_arg = arg;
  pid_t tid = process->pid;
  assert (tid > 0);

#ifndef HAVE_PROCESS_VM_READV
  return false;
#endif

  if ((addr & ((Dwarf_Addr)__LIBDWFL_REMOTE_MEM_CACHE_SIZE - 1))
    > (Dwarf_Addr)__LIBDWFL_REMOTE_MEM_CACHE_SIZE - sizeof (unsigned long)) {
      assert (0);
    }

  struct __libdwfl_remote_mem_cache *mem_cache = crash_arg->mem_cache;
  if (mem_cache == NULL)
    {
      size_t mem_cache_size = sizeof (struct __libdwfl_remote_mem_cache);
      mem_cache = (struct __libdwfl_remote_mem_cache *) malloc (mem_cache_size);
      if (mem_cache == NULL)
        return false;

      mem_cache->addr = 0;
      mem_cache->len = 0;
      crash_arg->mem_cache = mem_cache;
    }

  unsigned char *d;
  if (addr >= mem_cache->addr && addr - mem_cache->addr < mem_cache->len)
    {
      d = &mem_cache->buf[addr - mem_cache->addr];
      if ((((uintptr_t) d) & (sizeof (unsigned long) - 1)) == 0)
        *result = *(unsigned long *) d;
      else
        memcpy (result, d, sizeof (unsigned long));
      return true;
    }

  struct iovec local, remote;
  mem_cache->addr = addr & ~((Dwarf_Addr)__LIBDWFL_REMOTE_MEM_CACHE_SIZE - 1);
  local.iov_base = mem_cache->buf;
  local.iov_len = __LIBDWFL_REMOTE_MEM_CACHE_SIZE;
  remote.iov_base = (void *) (uintptr_t) mem_cache->addr;
  remote.iov_len = __LIBDWFL_REMOTE_MEM_CACHE_SIZE;

  ssize_t res = process_vm_readv (process->pid,
				  &local, 1, &remote, 1, 0);
  if (res != __LIBDWFL_REMOTE_MEM_CACHE_SIZE)
    {
      mem_cache->len = 0;
      return false;
    }

  mem_cache->len = res;
  d = &mem_cache->buf[addr - mem_cache->addr];
  if ((((uintptr_t) d) & (sizeof (unsigned long) - 1)) == 0)
    *result = *(unsigned long *) d;
  else
    memcpy (result, d, sizeof (unsigned long));
  
#if SIZEOF_LONG == 8
# if BYTE_ORDER == BIG_ENDIAN
      if (ebl_get_elfclass (process->ebl) == ELFCLASS32)
	*result >>= 32;
# endif
#endif
  return true;
}

static bool
crash_set_initial_registers (Dwfl_Thread *thread, void *thread_arg_voidp)
{
  struct thread_arg *thread_arg = thread_arg_voidp;
  struct crash_arg *crash_arg = thread_arg->crash_arg;
  Elf *crash = crash_arg->crash;
  size_t offset = thread_arg->note_offset;
  GElf_Nhdr nhdr;
  size_t name_offset;
  size_t desc_offset;
  Elf_Data *note_data = crash_arg->note_data;
  size_t nregs = ebl_frame_nregs (crash_arg->ebl);
  assert (nregs > 0);
  assert (offset < note_data->d_size);
  size_t getnote_err
      = gelf_getnote (note_data, offset, &nhdr, &name_offset, &desc_offset);
  /* __libdwfl_attach_state_for_crash already verified the note is there.  */
  if (getnote_err == 0)
    return false;
  /* Do not check NAME for now, help broken Linux kernels.  */
  const char *name
      = (nhdr.n_namesz == 0 ? "" : note_data->d_buf + name_offset);
  const char *desc = note_data->d_buf + desc_offset;
  GElf_Word regs_offset;
  size_t nregloc;
  const Ebl_Register_Location *reglocs;
  size_t nitems;
  const Ebl_Core_Item *items;
  int crash_note_err
      = ebl_core_note (crash_arg->ebl, &nhdr, name, desc, &regs_offset,
                       &nregloc, &reglocs, &nitems, &items);
  /* __libdwfl_attach_state_for_crash already verified the note is there.  */
  if (crash_note_err == 0 || nhdr.n_type != NT_PRSTATUS)
    return false;
  const Ebl_Core_Item *item;
  for (item = items; item < items + nitems; item++)
    if (strcmp (item->name, "pid") == 0)
      break;
  assert (item < items + nitems);
  pid_t tid;
  {
    uint32_t val32 = read_4ubyte_unaligned_noncvt (desc + item->offset);
    val32 = (elf_getident (crash, NULL)[EI_DATA] == ELFDATA2MSB
                 ? be32toh (val32)
                 : le32toh (val32));
    tid = (int32_t)val32;
    eu_static_assert (sizeof val32 <= sizeof tid);
  }
  /* crash_next_thread already found this TID there.  */
  assert (tid == INTUSE (dwfl_thread_tid) (thread));
  for (item = items; item < items + nitems; item++)
    if (item->pc_register)
      break;
  if (item < items + nitems)
    {
      Dwarf_Word pc;
      switch (gelf_getclass (crash) == ELFCLASS32 ? 32 : 64)
        {
        case 32:;
          uint32_t val32 = read_4ubyte_unaligned_noncvt (desc + item->offset);
          val32 = (elf_getident (crash, NULL)[EI_DATA] == ELFDATA2MSB
                       ? be32toh (val32)
                       : le32toh (val32));
          /* Do a host width conversion.  */
          pc = val32;
          break;
        case 64:;
          uint64_t val64 = read_8ubyte_unaligned_noncvt (desc + item->offset);
          val64 = (elf_getident (crash, NULL)[EI_DATA] == ELFDATA2MSB
                       ? be64toh (val64)
                       : le64toh (val64));
          pc = val64;
          break;
        default:
          abort ();
        }
      INTUSE (dwfl_thread_state_register_pc) (thread, pc);
    }
  desc += regs_offset;
  for (size_t regloci = 0; regloci < nregloc; regloci++)
    {
      const Ebl_Register_Location *regloc = reglocs + regloci;
      // Iterate even regs out of NREGS range so that we can find pc_register.
      if (regloc->bits != 32 && regloc->bits != 64)
        continue;
      const char *reg_desc = desc + regloc->offset;
      for (unsigned regno = regloc->regno;
           regno < regloc->regno + (regloc->count ?: 1U); regno++)
        {
          /* PPC provides DWARF register 65 irrelevant for
             CFI which clashes with register 108 (LR) we need.
             LR (108) is provided earlier (in NT_PRSTATUS) than the # 65.
             FIXME: It depends now on their order in core notes.
             FIXME: It uses private function.  */
          if (regno < nregs
              && __libdwfl_frame_reg_get (thread->unwound, regno, NULL))
            continue;
          Dwarf_Word val;
          switch (regloc->bits)
            {
            case 32:;
              uint32_t val32 = read_4ubyte_unaligned_noncvt (reg_desc);
              reg_desc += sizeof val32;
              val32 = (elf_getident (crash, NULL)[EI_DATA] == ELFDATA2MSB
                           ? be32toh (val32)
                           : le32toh (val32));
              /* Do a host width conversion.  */
              val = val32;
              break;
            case 64:;
              uint64_t val64 = read_8ubyte_unaligned_noncvt (reg_desc);
              reg_desc += sizeof val64;
              val64 = (elf_getident (crash, NULL)[EI_DATA] == ELFDATA2MSB
                           ? be64toh (val64)
                           : le64toh (val64));
              assert (sizeof (*thread->unwound->regs) == sizeof val64);
              val = val64;
              break;
            default:
              abort ();
            }
          /* Registers not valid for CFI are just ignored.  */
          if (regno < nregs)
            INTUSE (dwfl_thread_state_registers) (thread, regno, 1, &val);
          if (regloc->pc_register)
            INTUSE (dwfl_thread_state_register_pc) (thread, val);
          reg_desc += regloc->pad;
        }
    }
  return true;
}

static void
crash_detach (Dwfl *dwfl __attribute__ ((unused)), void *dwfl_arg)
{
  struct crash_arg *crash_arg = dwfl_arg;
  ebl_closebackend (crash_arg->ebl);
  free (crash_arg->mem_cache);
  free (crash_arg);
}

static const Dwfl_Thread_Callbacks crash_thread_callbacks = {
  crash_next_thread,
  NULL, /* getthread */
  crash_memory_read,
  crash_set_initial_registers,
  crash_detach,
  NULL, /* core_thread_detach */
};

int
dwfl_crash_file_attach (Dwfl *dwfl, Elf *crash)
{
  Dwfl_Error err = DWFL_E_NOERROR;
  Ebl *ebl = ebl_openbackend (crash);
  if (ebl == NULL)
    {
      err = DWFL_E_LIBEBL;
      printf("%s %d\n", __FUNCTION__, err);goto fail_err;
    }
  size_t nregs = ebl_frame_nregs (ebl);
  if (nregs == 0)
    {
      err = DWFL_E_NO_UNWIND;
      printf("%s %d\n", __FUNCTION__, err);goto fail;
    }
  GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr (crash, &ehdr_mem);
  if (ehdr == NULL)
    {
      err = DWFL_E_LIBELF;
      printf("%s %d\n", __FUNCTION__, err);goto fail;
    }
  if (ehdr->e_type != ET_CORE)
    {
      err = DWFL_E_NO_CORE_FILE;
      printf("%s %d\n", __FUNCTION__, err);goto fail;
    }
  size_t phnum;
  if (elf_getphdrnum (crash, &phnum) < 0)
    {
      err = DWFL_E_LIBELF;
      printf("%s %d\n", __FUNCTION__, err);goto fail;
    }
  pid_t pid = -1;
  Elf_Data *note_data = NULL;
  for (size_t cnt = 0; cnt < phnum; ++cnt)
    {
      GElf_Phdr phdr_mem, *phdr = gelf_getphdr (crash, cnt, &phdr_mem);
      if (phdr != NULL && phdr->p_type == PT_NOTE)
        {
          note_data = elf_getdata_rawchunk (
              crash, phdr->p_offset, phdr->p_filesz,
              (phdr->p_align == 8 ? ELF_T_NHDR8 : ELF_T_NHDR));
          break;
        }
    }
  if (note_data == NULL)
    {
      err = DWFL_E_LIBELF;
      printf("%s %d\n", __FUNCTION__, err);goto fail;
    }
  size_t offset = 0;
  GElf_Nhdr nhdr;
  size_t name_offset;
  size_t desc_offset;
  while (offset < note_data->d_size
         && (offset = gelf_getnote (note_data, offset, &nhdr, &name_offset,
                                    &desc_offset))
                > 0)
    {
      /* Do not check NAME for now, help broken Linux kernels.  */
      const char *name
          = (nhdr.n_namesz == 0 ? "" : note_data->d_buf + name_offset);
      const char *desc = note_data->d_buf + desc_offset;
      GElf_Word regs_offset;
      size_t nregloc;
      const Ebl_Register_Location *reglocs;
      size_t nitems;
      const Ebl_Core_Item *items;
      /* This note may be just not recognized, skip it.  */
      if (!ebl_core_note (ebl, &nhdr, name, desc, &regs_offset, &nregloc, &reglocs, &nitems, &items))
        continue;
      if (nhdr.n_type != NT_PRPSINFO)
        continue;
      const Ebl_Core_Item *item;
      for (item = items; item < items + nitems; item++)
        if (strcmp (item->name, "pid") == 0)
          break;
      if (item == items + nitems)
        continue;
      uint32_t val32 = read_4ubyte_unaligned_noncvt (desc + item->offset);
      val32 = (elf_getident (crash, NULL)[EI_DATA] == ELFDATA2MSB
                   ? be32toh (val32)
                   : le32toh (val32));
      pid = (int32_t)val32;
      eu_static_assert (sizeof val32 <= sizeof pid);
      break;
    }
  if (pid == -1)
    {
      /* No valid NT_PRPSINFO recognized in this CORE.  */
      err = DWFL_E_BADELF;
      printf("%s %d\n", __FUNCTION__, err);goto fail;
    }
  struct crash_arg *crash_arg = malloc (sizeof *crash_arg);
  if (crash_arg == NULL)
    {
      err = DWFL_E_NOMEM;
      printf("%s %d\n", __FUNCTION__, err);goto fail;
    }
  crash_arg->crash = crash;
  crash_arg->note_data = note_data;
  crash_arg->thread_note_offset = 0;
  crash_arg->mem_cache = 0;
  crash_arg->ebl = ebl;
  if (!INTUSE (dwfl_attach_state) (dwfl, crash, pid, &crash_thread_callbacks, crash_arg))
    {
      free (crash_arg);
      ebl_closebackend (ebl);
      __libdwfl_seterrno (DWFL_E_BADELF);
      return -1;
    }
  return pid;

  fail:
    ebl_closebackend (ebl);

  fail_err:
    // TODO: leave this out for now because __libdwfl_canon_error clears out the error
    // making __libdwfl_seterrno set it to no-error
    // if (dwfl->process == NULL && dwfl->attacherr == DWFL_E_NOERROR)
    //   dwfl->attacherr = __libdwfl_canon_error (err);
    __libdwfl_seterrno (err);
    return -1;
}
INTDEF (dwfl_crash_file_attach)