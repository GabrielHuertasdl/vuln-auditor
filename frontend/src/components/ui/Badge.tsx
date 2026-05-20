import React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors',
  {
    variants: {
      variant: {
        default: 'bg-primary/10 text-primary',
        secondary: 'bg-secondary text-secondary-foreground',
        outline: 'border border-border text-foreground',
        success: 'bg-green-500/10 text-green-500 dark:bg-green-500/20',
        warning: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 dark:bg-yellow-500/20',
        destructive: 'bg-red-500/10 text-red-600 dark:text-red-400 dark:bg-red-500/20',
        info: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 dark:bg-blue-500/20',
        purple: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 dark:bg-purple-500/20',
        muted: 'bg-muted text-muted-foreground',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
