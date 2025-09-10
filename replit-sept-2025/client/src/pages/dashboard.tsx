import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { useLocation } from "wouter";
import type { Note } from "@shared/schema";
import { 
  Shield, 
  Lock, 
  ShieldQuestion, 
  Database, 
  Globe, 
  Plus, 
  Edit, 
  Trash2, 
  User, 
  LogOut,
  CheckCircle,
  StickyNote
} from "lucide-react";

export default function Dashboard() {
  const { toast } = useToast();
  const { user, isAuthenticated, isLoading } = useAuth();
  const [, navigate] = useLocation();
  const queryClient = useQueryClient();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, isLoading, toast]);

  // Fetch user's notes
  const { data: notes = [], isLoading: notesLoading } = useQuery({
    queryKey: ["/api/notes"],
    enabled: isAuthenticated,
    retry: false,
  });

  // Delete note mutation
  const deleteNoteMutation = useMutation({
    mutationFn: async (noteId: string) => {
      await apiRequest("DELETE", `/api/notes/${noteId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notes"] });
      toast({
        title: "Success",
        description: "Note deleted successfully",
      });
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to delete note",
        variant: "destructive",
      });
    },
  });

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

  if (!isAuthenticated) {
    return null;
  }

  const handleDeleteNote = (noteId: string) => {
    if (confirm("Are you sure you want to delete this note? This action cannot be undone.")) {
      deleteNoteMutation.mutate(noteId);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo and Title */}
            <div className="flex items-center">
              <div className="flex items-center">
                <Shield className="text-primary text-xl mr-3" />
                <h1 className="text-xl font-bold">SecureNotes</h1>
              </div>
            </div>

            {/* User Menu */}
            <div className="flex items-center space-x-4">
              {/* Security Status */}
              <Badge variant="secondary" className="hidden sm:flex bg-green-50 border-green-200 text-green-700 hover:bg-green-50">
                <CheckCircle className="h-3 w-3 mr-1" />
                Secure Session
              </Badge>

              {/* User Profile */}
              <div className="flex items-center space-x-3">
                <div className="text-right text-sm">
                  <div className="font-medium" data-testid="text-username">
                    {(user as any)?.firstName || (user as any)?.email || "User"}
                  </div>
                  <div className="text-muted-foreground text-xs" data-testid="text-email">
                    {(user as any)?.email}
                  </div>
                </div>
                <Button size="sm" variant="outline" className="p-2 rounded-full">
                  <User className="h-4 w-4" />
                </Button>
                <Button 
                  variant="ghost"
                  size="sm"
                  onClick={() => window.location.href = "/api/logout"}
                  title="Secure Logout"
                  data-testid="button-logout"
                >
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <div className="flex justify-between items-start">
            <div>
              <h2 className="text-3xl font-bold mb-2">My Notes</h2>
              <p className="text-muted-foreground">
                Securely manage your personal notes with enterprise-grade protection
              </p>
            </div>
            <Button 
              onClick={() => navigate("/editor")}
              data-testid="button-create-note"
            >
              <Plus className="h-4 w-4 mr-2" />
              New Note
            </Button>
          </div>

          {/* Security Features Dashboard */}
          <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <Lock className="text-green-600 mr-3 h-5 w-5" />
                  <div>
                    <div className="text-sm font-medium">Encryption</div>
                    <div className="text-xs text-muted-foreground">AES-256 Active</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <ShieldQuestion className="text-blue-600 mr-3 h-5 w-5" />
                  <div>
                    <div className="text-sm font-medium">Authorization</div>
                    <div className="text-xs text-muted-foreground">User Verified</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <Database className="text-purple-600 mr-3 h-5 w-5" />
                  <div>
                    <div className="text-sm font-medium">Database</div>
                    <div className="text-xs text-muted-foreground">SQL Injection Protected</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <Globe className="text-orange-600 mr-3 h-5 w-5" />
                  <div>
                    <div className="text-sm font-medium">Network</div>
                    <div className="text-xs text-muted-foreground">HTTPS Enforced</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Notes Grid */}
        {notesLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3].map((i) => (
              <Card key={i}>
                <CardContent className="p-6">
                  <div className="animate-pulse">
                    <div className="h-4 bg-muted rounded w-3/4 mb-2"></div>
                    <div className="h-4 bg-muted rounded w-1/2 mb-4"></div>
                    <div className="h-20 bg-muted rounded mb-4"></div>
                    <div className="h-3 bg-muted rounded w-1/3"></div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (notes as Note[]).length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {(notes as Note[]).map((note: Note) => (
              <Card key={note.id} className="shadow-sm hover:shadow-md transition-shadow" data-testid={`card-note-${note.id}`}>
                <CardContent className="p-6">
                  <div className="flex justify-between items-start mb-4">
                    <Badge variant="outline" className="text-green-600 border-green-200">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Owned by you
                    </Badge>
                    <div className="flex space-x-2">
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        onClick={() => navigate(`/editor/${note.id}`)}
                        data-testid={`button-edit-${note.id}`}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        onClick={() => handleDeleteNote(note.id)}
                        disabled={deleteNoteMutation.isPending}
                        data-testid={`button-delete-${note.id}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <h3 className="font-semibold text-lg mb-2" data-testid={`text-title-${note.id}`}>
                    {note.title}
                  </h3>
                  <p className="text-muted-foreground text-sm mb-4 line-clamp-3" data-testid={`text-preview-${note.id}`}>
                    {note.content.length > 100 ? `${note.content.substring(0, 100)}...` : note.content}
                  </p>
                  <div className="flex justify-between items-center text-xs text-muted-foreground">
                    <span data-testid={`text-updated-${note.id}`}>
                      Updated {formatDate(note.updatedAt || note.createdAt || '')}
                    </span>
                    <div className="flex items-center">
                      <Shield className="h-3 w-3 mr-1 text-green-600" />
                      <span>Encrypted</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          /* Empty State */
          <div className="text-center py-12" data-testid="empty-state">
            <StickyNote className="h-16 w-16 text-muted-foreground/50 mx-auto mb-4" />
            <h3 className="text-xl font-medium mb-2">No notes yet</h3>
            <p className="text-muted-foreground mb-6">Create your first secure note to get started</p>
            <Button onClick={() => navigate("/editor")} data-testid="button-create-first-note">
              <Plus className="h-4 w-4 mr-2" />
              Create Your First Note
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
