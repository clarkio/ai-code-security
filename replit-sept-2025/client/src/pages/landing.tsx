import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Lock, UserCheck, Database, Globe, Clock } from "lucide-react";

export default function Landing() {
  const { isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary/5 to-accent/10 p-4">
      <div className="w-full max-w-md">
        {/* Security Badge */}
        <div className="text-center mb-8">
          <Badge variant="secondary" className="mb-4 bg-green-50 border-green-200 text-green-700 hover:bg-green-50">
            <Shield className="h-3 w-3 mr-1" />
            Enterprise-Grade Security
          </Badge>
          <h1 className="text-3xl font-bold text-foreground mb-2">SecureNotes</h1>
          <p className="text-muted-foreground">Production-ready note management with military-grade security</p>
        </div>

        {/* Login Form */}
        <Card className="shadow-lg">
          <CardContent className="p-8">
            <div className="mb-6">
              <h2 className="text-2xl font-semibold mb-2">Sign In</h2>
              <p className="text-muted-foreground text-sm">Access your secure notes with Replit Auth</p>
            </div>

            {/* Security Features Display */}
            <div className="mb-6 p-4 bg-accent/50 rounded-md border border-border">
              <h3 className="text-sm font-medium mb-2 flex items-center">
                <Lock className="h-4 w-4 mr-2 text-primary" />
                Security Features Active
              </h3>
              <ul className="text-xs text-muted-foreground space-y-1">
                <li>✓ HTTPS Encryption</li>
                <li>✓ CSRF Protection</li>
                <li>✓ Rate Limiting Active</li>
                <li>✓ SQL Injection Prevention</li>
              </ul>
            </div>

            <div className="space-y-4">
              <Button 
                className="w-full" 
                onClick={() => window.location.href = '/api/login'}
                data-testid="button-login"
              >
                <UserCheck className="h-4 w-4 mr-2" />
                Sign In Securely
              </Button>
            </div>

            {/* Rate Limiting Display */}
            <div className="mt-4 p-3 bg-amber-50 border border-amber-200 rounded-md">
              <div className="flex items-center text-amber-700 text-xs">
                <Clock className="h-3 w-3 mr-2" />
                Rate limiting: 5 attempts per minute
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
