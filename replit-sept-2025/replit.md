# SecureNotes - Production-Ready Note Management Application

## Overview

SecureNotes is a full-stack web application for secure note management built with modern technologies. The application features enterprise-grade security, user authentication via Replit Auth, and a clean, responsive user interface. Users can create, edit, delete, and manage their personal notes with military-grade security features including HTTPS encryption, CSRF protection, and secure session management.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript for type safety and modern component patterns
- **Styling**: Tailwind CSS with shadcn/ui component library for consistent, accessible design
- **State Management**: TanStack Query (React Query) for server state management and caching
- **Routing**: Wouter for lightweight client-side routing
- **Build Tool**: Vite for fast development and optimized production builds
- **Form Handling**: React Hook Form with Zod validation for type-safe form management

### Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript for full-stack type safety
- **API Design**: RESTful API with rate limiting and security middleware
- **Authentication**: Replit Auth with OpenID Connect for secure user authentication
- **Session Management**: Express sessions with PostgreSQL storage using connect-pg-simple
- **Security**: Helmet.js for security headers, CSRF protection, and rate limiting

### Data Storage Solutions
- **Database**: PostgreSQL with Neon serverless hosting for scalable, managed database
- **ORM**: Drizzle ORM for type-safe database operations and schema management
- **Schema**: Shared TypeScript schema definitions between frontend and backend
- **Migrations**: Drizzle Kit for database schema migrations and version control

### Authentication and Authorization
- **Provider**: Replit Auth with OpenID Connect protocol
- **Session Storage**: PostgreSQL-backed sessions with configurable TTL
- **User Management**: Automatic user creation and profile updates on authentication
- **Authorization**: User-scoped data access with database-level foreign key constraints
- **Security Features**: HTTPS enforcement, secure cookies, and CSRF protection

### Key Design Patterns
- **Monorepo Structure**: Organized into client/, server/, and shared/ directories for code reuse
- **Type Safety**: End-to-end TypeScript with shared schema definitions
- **Error Handling**: Centralized error handling with user-friendly error messages
- **Security-First**: Multiple layers of security including rate limiting, input validation, and secure headers
- **Responsive Design**: Mobile-first design with adaptive UI components

## External Dependencies

### Core Framework Dependencies
- **@neondatabase/serverless**: Serverless PostgreSQL driver for database connectivity
- **drizzle-orm**: Type-safe ORM for database operations and query building
- **drizzle-zod**: Schema validation integration between Drizzle and Zod

### Authentication & Security
- **openid-client**: OpenID Connect client for Replit Auth integration
- **passport**: Authentication middleware for Express
- **express-session**: Session management middleware
- **connect-pg-simple**: PostgreSQL session store adapter
- **helmet**: Security middleware for HTTP headers
- **express-rate-limit**: Rate limiting middleware for API protection

### UI & Frontend Libraries
- **@radix-ui/***: Comprehensive set of accessible, unstyled UI primitives
- **@tanstack/react-query**: Server state management and caching library
- **react-hook-form**: Performant forms library with minimal re-renders
- **@hookform/resolvers**: Validation resolver for React Hook Form
- **tailwindcss**: Utility-first CSS framework for rapid UI development
- **class-variance-authority**: Utility for creating type-safe component variants
- **lucide-react**: Modern icon library with consistent design

### Development & Build Tools
- **vite**: Fast build tool with hot module replacement
- **@vitejs/plugin-react**: React plugin for Vite
- **esbuild**: Fast JavaScript bundler for server-side builds
- **tsx**: TypeScript execution environment for development
- **@replit/vite-plugin-runtime-error-modal**: Development error overlay
- **@replit/vite-plugin-cartographer**: Replit-specific development tooling

### Utility Libraries
- **zod**: Runtime type validation and schema definition
- **date-fns**: Modern date utility library
- **clsx**: Conditional className utility
- **memoizee**: Function memoization for performance optimization
- **nanoid**: Secure URL-friendly unique ID generator
- **wouter**: Minimalist routing library for React