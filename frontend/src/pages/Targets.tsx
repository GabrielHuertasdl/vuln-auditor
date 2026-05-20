import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { targetsApi, scansApi, type Target } from '@/lib/api'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Table, TableHeader, TableBody, TableHead, TableRow } from '@/components/ui/Table'
import { Card, CardContent } from '@/components/ui/Card'
import { TargetRow } from '@/components/TargetRow'
import { EmptyState } from '@/components/EmptyState'
import { TableSkeleton } from '@/components/LoadingSkeleton'
import { useToast } from '@/hooks/useToast'
import { t } from '@/lib/i18n'

const targetSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  url: z.string().url('Must be a valid URL'),
  schedule: z.enum(['daily', 'weekly', 'monthly', '']).optional(),
  tags: z.string().optional(),
})

type TargetFormData = z.infer<typeof targetSchema>

const SCHEDULE_OPTIONS = [
  { value: '', label: 'No schedule (manual)' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
]

const SCAN_CATEGORIES = [
  { key: 'dast', label: 'DAST (ZAP + Nmap)', tools: ['nmap', 'zap'], defaultChecked: true },
  { key: 'sast', label: 'SAST (Semgrep)',     tools: ['semgrep'],      defaultChecked: false },
  { key: 'sca',  label: 'SCA (Trivy)',         tools: ['trivy'],        defaultChecked: false },
  { key: 'iac',  label: 'IaC (Checkov)',       tools: ['checkov'],      defaultChecked: false },
]

function getToolsFromCategories(enabled: Record<string, boolean>): string[] {
  return SCAN_CATEGORIES.filter((c) => enabled[c.key]).flatMap((c) => c.tools)
}

export default function Targets() {
  const qc = useQueryClient()
  const { toast } = useToast()

  const [modalOpen, setModalOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<Target | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Target | null>(null)
  const [scanningId, setScanningId] = useState<string | null>(null)
  const [scanCategories, setScanCategories] = useState<Record<string, boolean>>(
    Object.fromEntries(SCAN_CATEGORIES.map((c) => [c.key, c.defaultChecked]))
  )

  const { data: targets, isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.list().then((r) => r.data),
  })

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<TargetFormData>({ resolver: zodResolver(targetSchema) })

  const createMutation = useMutation({
    mutationFn: (data: TargetFormData) =>
      targetsApi.create({
        name: data.name,
        url: data.url,
        schedule: data.schedule || null,
        tags: data.tags ? data.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['targets'] })
      toast(t('toast.target_created'), 'success')
      setModalOpen(false)
      reset()
    },
    onError: () => toast(t('toast.error'), 'error'),
  })

  const updateMutation = useMutation({
    mutationFn: (data: TargetFormData) =>
      targetsApi.update(editTarget!.id, {
        name: data.name,
        url: data.url,
        schedule: data.schedule || null,
        tags: data.tags ? data.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['targets'] })
      toast(t('toast.target_updated'), 'success')
      setEditTarget(null)
      reset()
    },
    onError: () => toast(t('toast.error'), 'error'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => targetsApi.delete(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['targets'] })
      toast(t('toast.target_deleted'), 'success')
      setDeleteTarget(null)
    },
    onError: () => toast(t('toast.error'), 'error'),
  })

  const onScanNow = async (target: Target) => {
    setScanningId(target.id)
    try {
      const tools = getToolsFromCategories(scanCategories)
      await scansApi.start({
        target_url: target.url,
        tools: tools.length > 0 ? tools : ['nmap', 'zap'],
        scan_mode: 'full',
      })
      toast(t('toast.scan_started'), 'success')
      void qc.invalidateQueries({ queryKey: ['scans'] })
    } catch {
      toast(t('toast.scan_failed'), 'error')
    } finally {
      setScanningId(null)
    }
  }

  const openCreate = () => {
    setEditTarget(null)
    reset({ name: '', url: '', schedule: '', tags: '' })
    setModalOpen(true)
  }

  const openEdit = (target: Target) => {
    setEditTarget(target)
    reset({
      name: target.name,
      url: target.url,
      schedule: target.schedule ?? '',
      tags: target.tags.join(', '),
    })
    setModalOpen(true)
  }

  const onSubmit = async (data: TargetFormData) => {
    if (editTarget) {
      await updateMutation.mutateAsync(data)
    } else {
      await createMutation.mutateAsync(data)
    }
  }

  if (isLoading) return <TableSkeleton />

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold">{t('targets.title')}</h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            {targets?.length ?? 0} target{targets?.length !== 1 ? 's' : ''} configured
          </p>
        </div>
        <Button onClick={openCreate}>
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M5 12h14M12 5v14" />
          </svg>
          {t('targets.add')}
        </Button>
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {!targets || targets.length === 0 ? (
            <EmptyState
              title={t('targets.empty')}
              description={t('targets.empty_desc')}
              action={{ label: t('targets.add'), onClick: openCreate }}
              className="py-16"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('targets.name')}</TableHead>
                  <TableHead>{t('targets.schedule')}</TableHead>
                  <TableHead>{t('targets.last_scan')}</TableHead>
                  <TableHead>{t('targets.scan_count')}</TableHead>
                  <TableHead>{t('targets.open_findings')}</TableHead>
                  <TableHead>{t('common.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((target) => (
                  <TargetRow
                    key={target.id}
                    target={target}
                    onScanNow={onScanNow}
                    onEdit={openEdit}
                    onDelete={setDeleteTarget}
                    isScanning={scanningId === target.id}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create / Edit Modal */}
      <Modal
        open={modalOpen}
        onClose={() => { setModalOpen(false); setEditTarget(null) }}
        title={editTarget ? t('targets.edit') : t('targets.add')}
        size="md"
      >
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <Input
            label={t('targets.name')}
            placeholder="My Application"
            error={errors.name?.message}
            {...register('name')}
          />
          <Input
            label={t('targets.url')}
            type="url"
            placeholder="https://app.example.com"
            error={errors.url?.message}
            {...register('url')}
          />
          <Select
            label={t('targets.schedule')}
            options={SCHEDULE_OPTIONS}
            {...register('schedule')}
          />
          <Input
            label={`${t('targets.tags')} (comma-separated, optional)`}
            placeholder="production, api, public"
            error={errors.tags?.message}
            {...register('tags')}
          />

          {/* Scan category selection */}
          <div>
            <p className="text-sm font-medium mb-2">Scan Categories</p>
            <div className="space-y-2">
              {SCAN_CATEGORIES.map((cat) => (
                <label key={cat.key} className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-border accent-primary"
                    checked={scanCategories[cat.key]}
                    onChange={(e) =>
                      setScanCategories((prev) => ({ ...prev, [cat.key]: e.target.checked }))
                    }
                  />
                  <span className="text-sm">{cat.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => { setModalOpen(false); setEditTarget(null) }}
            >
              {t('common.cancel')}
            </Button>
            <Button type="submit" isLoading={isSubmitting}>
              {editTarget ? t('common.save') : t('targets.add')}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirm */}
      <ConfirmDialog
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
        title={t('targets.delete_confirm')}
        description={t('targets.delete_desc')}
        confirmLabel={t('common.delete')}
        isLoading={deleteMutation.isPending}
      />
    </div>
  )
}
