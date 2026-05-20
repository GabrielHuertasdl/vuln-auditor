import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuth } from '@/lib/auth'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { t } from '@/lib/i18n'
import { useToast } from '@/hooks/useToast'

const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain an uppercase letter')
    .regex(/[0-9]/, 'Must contain a number'),
  org_name: z.string().optional(),
})

type RegisterFormData = z.infer<typeof registerSchema>

export default function Register() {
  const { register: authRegister } = useAuth()
  const navigate = useNavigate()
  const { toast } = useToast()
  const [serverError, setServerError] = useState('')

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  })

  const onSubmit = async (data: RegisterFormData) => {
    try {
      setServerError('')
      await authRegister(data)
      toast('Account created successfully!', 'success')
      navigate('/dashboard', { replace: true })
    } catch (err: unknown) {
      const message =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        'Registration failed. Please try again.'
      setServerError(message)
      toast(message, 'error')
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm space-y-8">
        {/* Logo */}
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl gradient-brand">
            <svg className="h-7 w-7 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-foreground">VulnAuditor</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Start securing your applications today
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-border bg-card p-8 shadow-lg">
          <h2 className="mb-6 text-xl font-semibold">{t('auth.register')}</h2>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
            <Input
              label={t('auth.name')}
              type="text"
              placeholder="Jane Smith"
              autoComplete="name"
              error={errors.name?.message}
              {...register('name')}
            />
            <Input
              label={t('auth.email')}
              type="email"
              placeholder="you@company.com"
              autoComplete="email"
              error={errors.email?.message}
              {...register('email')}
            />
            <Input
              label={t('auth.password')}
              type="password"
              placeholder="Min 8 chars, uppercase, number"
              autoComplete="new-password"
              error={errors.password?.message}
              {...register('password')}
            />
            <Input
              label={`${t('auth.org_name')} (optional)`}
              type="text"
              placeholder="Acme Corp"
              autoComplete="organization"
              error={errors.org_name?.message}
              {...register('org_name')}
            />

            {serverError && (
              <p className="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-500">
                {serverError}
              </p>
            )}

            <Button type="submit" className="w-full" isLoading={isSubmitting} size="lg">
              {t('auth.register')}
            </Button>
          </form>

          <p className="mt-6 text-center text-sm text-muted-foreground">
            Already have an account?{' '}
            <Link to="/login" className="font-medium text-primary hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
